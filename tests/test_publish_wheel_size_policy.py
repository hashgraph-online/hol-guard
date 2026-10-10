"""Release policy extraction stays pinned when the source checkout changes."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest
import yaml

_ROOT = Path(__file__).resolve().parents[1]
_POLICIES = ("scripts/ci/check_wheel_size.py", "ci/package_size/budgets.json")


def _fixture_env(**values: str) -> dict[str, str]:
    # Disposable repositories use their fixture identity, independent of the
    # developer's author overrides, signing configuration and commit hooks.
    env = {key: value for key, value in os.environ.items() if not key.startswith(("GIT_AUTHOR_", "GIT_COMMITTER_"))}
    return {**env, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1", **values}


def _git(root: Path, *arguments: str) -> str:
    return subprocess.check_output(["git", *arguments], cwd=root, env=_fixture_env(), text=True).strip()


def _policy_steps() -> list[dict]:
    workflow = yaml.safe_load((_ROOT / ".github/workflows/publish.yml").read_text())
    names = {
        "Retain workflow wheel-size policy before source checkout",
        "Retain immutable workflow wheel-size policy",
    }
    steps = [step for job in workflow["jobs"].values() for step in job.get("steps", []) if step.get("name") in names]
    assert len(steps) == len(names) and {step["name"] for step in steps} == names
    return steps


@pytest.mark.parametrize("step", _policy_steps(), ids=lambda step: step["name"])
def test_policy_is_retained_from_workflow_commit(step: dict, tmp_path: Path) -> None:
    remote = tmp_path / "remote"
    source = tmp_path / "source"
    for root in (remote, source):
        root.mkdir()
        _git(root, "init", "--quiet")
        _git(root, "config", "user.name", "Release policy fixture")
        _git(root, "config", "user.email", "test@users.noreply.github.com")
        _git(root, "config", "commit.gpgsign", "false")
    trusted = {}
    for relative in _POLICIES:
        path = remote / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        trusted[relative] = "trusted policy\n"
        path.write_text(trusted[relative])
    _git(remote, "add", ".")
    _git(remote, "commit", "--quiet", "-m", "Trusted workflow policy")
    workflow_sha = _git(remote, "rev-parse", "HEAD")
    for relative in _POLICIES:
        path = source / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("different source policy\n")
    _git(source, "add", ".")
    _git(source, "commit", "--quiet", "-m", "Different source checkout")
    source_sha = _git(source, "rev-parse", "HEAD")
    _git(source, "remote", "add", "origin", str(remote))
    missing = subprocess.run(
        ["git", "cat-file", "-e", workflow_sha], cwd=source, env=_fixture_env(), capture_output=True
    )
    assert missing.returncode != 0
    runner = tmp_path / "runner temp"
    runner.mkdir()
    environment_file = runner / "github-env"
    env = _fixture_env(SIZE_POLICY_SHA=workflow_sha, RUNNER_TEMP=str(runner), GITHUB_ENV=str(environment_file))
    result = subprocess.run(["bash", "-c", step["run"]], cwd=source, env=env, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert _git(source, "rev-parse", "HEAD") == source_sha
    assert _git(source, "cat-file", "-t", workflow_sha) == "commit"
    policy_root = runner / "hol-guard-wheel-size-policy"
    for relative in _POLICIES:
        assert (policy_root / relative).read_text() == trusted[relative]
        assert (source / relative).read_text() == "different source policy\n"
    assert environment_file.read_text() == f"HOL_GUARD_WHEEL_SIZE_CHECKER={policy_root / _POLICIES[0]}\n"


@pytest.mark.parametrize("step", _policy_steps(), ids=lambda step: step["name"])
def test_policy_rejects_mutable_reference_before_fetch(step: dict, tmp_path: Path) -> None:
    env = _fixture_env(SIZE_POLICY_SHA="main", RUNNER_TEMP=str(tmp_path), GITHUB_ENV=str(tmp_path / "github-env"))
    result = subprocess.run(["bash", "-c", step["run"]], cwd=tmp_path, env=env, capture_output=True, text=True)
    assert result.returncode != 0
    assert not (tmp_path / "hol-guard-wheel-size-policy").exists()
