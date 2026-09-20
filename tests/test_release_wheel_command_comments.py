"""Wheel configuration evidence must come from commands in the named job."""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

from scripts.ci import release_required_evidence as required

SOURCE_SHA = "a" * 40
WHEEL_CHECKS = (
    ("publish-alpha-testpypi", 'uv tool run --from "$wheel" hol-guard --version'),
    ("publish-alpha-pypi", 'uv tool run --from "$guard_wheel" hol-guard --version'),
    ("publish-main-pypi", 'uv tool run --from "$guard_wheel" hol-guard --version'),
)
CANARY_OSES = ("ubuntu-latest", "macos-latest", "windows-latest")


@pytest.fixture
def workflow_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    # This E2 fixture exercises real YAML/configuration validation, not collection
    # or installed execution. Those two external boundaries remain explicit.
    def collect(root: Path, extra_args: Sequence[str], *, targets: Sequence[str]) -> list[str]:
        assert root == tmp_path
        assert tuple(targets) == required.REQUIRED_RELEASE_FILES
        assert tuple(extra_args) in ((), ("-o", "addopts=", "-m", "release"))
        return list(required.REQUIRED_RELEASE_NODE_IDS)

    def source_id(command: list[str], *, cwd: Path, text: bool) -> str:
        assert command == ["git", "rev-parse", "HEAD"]
        assert cwd == tmp_path
        assert text is True
        return SOURCE_SHA + "\n"

    monkeypatch.setattr(required, "_collect", collect)
    monkeypatch.setattr(required, "subprocess", SimpleNamespace(check_output=source_id))
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    canary = {
        "jobs": {
            "pr-installed-canary": {
                "strategy": {"matrix": {"os": list(CANARY_OSES)}},
                "steps": [
                    {"run": "hol-guard verify-release --registry testpypi"},
                    {"run": "python -m scripts.run_installed_canary"},
                ],
            },
        },
    }
    (workflows / "installed-pr-canary.yml").write_text(yaml.safe_dump(canary), encoding="utf-8")
    (workflows / "ci.yml").write_text(required.NAMED_CI_DESELECT + "\n", encoding="utf-8")
    return tmp_path


def write_jobs(root: Path, selected_job: str, run: str) -> None:
    jobs = {name: {"steps": [{"run": command}]} for name, command in WHEEL_CHECKS}
    jobs[selected_job]["steps"] = [{"run": run}]
    # A real command elsewhere must not satisfy the selected job's requirement.
    jobs["unrelated-check"] = {"steps": [{"run": dict(WHEEL_CHECKS)[selected_job]}]}
    (root / ".github" / "workflows" / "publish.yml").write_text(
        yaml.safe_dump({"jobs": jobs}), encoding="utf-8"
    )


@pytest.mark.parametrize("job_name,command", WHEEL_CHECKS)
def test_rejects_wheel_command_present_only_in_the_named_jobs_comment(
    workflow_root: Path, job_name: str, command: str
) -> None:
    write_jobs(workflow_root, job_name, f"# {command}\nprintf '%s\\n' 'check omitted'\n")

    with pytest.raises(RuntimeError, match=f"^{job_name} has no configured wheel install check$"):
        required.build_report(workflow_root)


@pytest.mark.parametrize("job_name,command", WHEEL_CHECKS)
@pytest.mark.parametrize("form", ["command", "single-quoted-hash", "double-quoted-hash", "trailing-comment"])
def test_preserves_real_commands_without_claiming_installed_execution(
    workflow_root: Path, job_name: str, command: str, form: str
) -> None:
    commands = {
        "command": command + "\n",
        "single-quoted-hash": f"printf '%s\\n' '# data'; {command}\n",
        "double-quoted-hash": f'printf "%s\\n" "# data"; {command}\n',
        "trailing-comment": f"{command} # retained installation check\n",
    }
    write_jobs(workflow_root, job_name, commands[form])

    report = required.build_report(workflow_root)

    assert report.source_sha == SOURCE_SHA
    assert report.configured_wheel_jobs == tuple(name for name, _ in WHEEL_CHECKS)
    assert report.evidence_kind == "collection-and-configuration"
    assert report.installed_runtime_verified is False


@pytest.mark.parametrize("redirection", ["<", ">"])
def test_rejects_wheel_command_after_redirection_comment_marker(
    workflow_root: Path, redirection: str
) -> None:
    job_name, command = WHEEL_CHECKS[0]
    write_jobs(workflow_root, job_name, f"printf '%s\\n' omitted {redirection}# {command}\n")

    with pytest.raises(RuntimeError, match=f"^{job_name} has no configured wheel install check$"):
        required.build_report(workflow_root)


def test_preserves_escaped_hash_before_real_wheel_command(workflow_root: Path) -> None:
    job_name, command = WHEEL_CHECKS[0]
    write_jobs(workflow_root, job_name, f"printf '%s\\n' \\#data; {command}\n")

    report = required.build_report(workflow_root)

    assert report.configured_wheel_jobs == tuple(name for name, _ in WHEEL_CHECKS)
    assert report.evidence_kind == "collection-and-configuration"
    assert report.installed_runtime_verified is False
