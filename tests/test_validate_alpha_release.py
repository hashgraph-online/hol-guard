from __future__ import annotations

import sys
from pathlib import Path

import pytest
import yaml

from scripts.validate_alpha_release import ALPHA_BRANCHES, main, validate_alpha_release


def test_accepts_public_guard_3_alpha_version_from_v3_branch() -> None:
    release = validate_alpha_release("3.0.0a1", ALPHA_BRANCHES[0])

    assert release.version == "3.0.0a1"
    assert release.git_ref == ALPHA_BRANCHES[0]


@pytest.mark.parametrize(
    "version",
    [
        "1!3.0.0a1",
        "2.1.0a1",
        "3.0.0b1",
        "3.0.0rc1",
        "3.0.0",
        "3.0.0a1.dev1",
        "3.0.0a1.post1",
        "3.0.0a1+local",
    ],
)
def test_rejects_versions_that_are_not_public_guard_3_alphas(version: str) -> None:
    with pytest.raises(ValueError, match=r"3\.x alpha"):
        validate_alpha_release(version, ALPHA_BRANCHES[0])


def test_rejects_alpha_release_from_any_other_branch() -> None:
    with pytest.raises(ValueError, match="feat/guard-policy-v3"):
        validate_alpha_release("3.0.0a1", "refs/heads/main")


def test_accepts_release_31_policy_branch() -> None:
    release = validate_alpha_release("3.0.0a1", "refs/heads/release/3.1-policy-v3")
    assert release.git_ref == "refs/heads/release/3.1-policy-v3"


def test_cli_reports_invalid_alpha_without_traceback(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(
        sys,
        "argv",
        ["validate_alpha_release.py", "--version", "3.0.0", "--git-ref", ALPHA_BRANCHES[0]],
    )

    assert main() == 1
    captured = capsys.readouterr()
    assert "Error: Alpha releases require" in captured.err
    assert "Traceback" not in captured.err


def test_release_workflows_keep_stable_and_alpha_channels_isolated() -> None:
    root = Path(__file__).parent.parent
    publish = yaml.safe_load((root / ".github/workflows/publish.yml").read_text(encoding="utf-8"))
    on_section = publish.get(True) or publish.get("on")
    inputs = on_section["workflow_dispatch"]["inputs"]

    assert inputs["release_channel"]["options"] == ["stable", "alpha"]
    assert inputs["alpha_version"]["required"] is False

    jobs = publish["jobs"]
    alpha_matrix = jobs["alpha-cross-platform"]["strategy"]["matrix"]["os"]
    assert alpha_matrix == ["ubuntu-latest", "windows-latest"]
    publish_if = jobs["publish-pypi"]["if"]
    assert any(branch in publish_if for branch in ("feat/guard-policy-v3", "release/3.1-policy-v3"))
    assert jobs["publish-pypi"]["needs"] == ["build", "alpha-cross-platform"]
    assert jobs["release-alpha"]["needs"] == ["build", "publish-pypi"]

    alpha_publish_steps = jobs["publish-pypi"]["steps"]
    prune_step = next(
        step for step in alpha_publish_steps if step.get("name") == "Keep only the Guard alpha distribution"
    )
    assert prune_step["if"] == "needs.build.outputs.channel == 'alpha'"
    assert "plugin_scanner" in prune_step["run"]


def test_v3_branch_runs_standard_cross_platform_ci() -> None:
    root = Path(__file__).parent.parent
    ci = yaml.safe_load((root / ".github/workflows/ci.yml").read_text(encoding="utf-8"))

    on_section = ci.get(True) or ci.get("on")
    assert "feat/guard-policy-v3" in on_section["push"]["branches"]
    assert "feat/guard-policy-v3" in on_section["pull_request"]["branches"]
    assert "windows-latest" in ci["jobs"]["cross-platform"]["strategy"]["matrix"]["os"]
