from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from tests.native_command_test_support import inspect_command_native_test as inspect_command


@pytest.mark.parametrize(
    "command",
    (
        "git fetch origin; rm -rf target",
        "git fetch origin && rm -rf target",
    ),
)
def test_compound_fetch_with_delete_is_not_origin_refresh(tmp_path: Path, command: str) -> None:
    payload = inspect_command(command, cwd=tmp_path, home_dir=tmp_path)

    assert payload["status"] == "review"
    assert payload["classification"]["action_class"] != "git origin refresh"
    assert payload["controlling_rule_id"] == "command.filesystem.recursive-delete"


@pytest.mark.parametrize(
    "command",
    (
        "git -c core.sshCommand=payload fetch origin && git fetch origin",
        "git fetch origin && git -c core.sshCommand=payload fetch origin",
    ),
)
def test_config_override_compound_fetch_keeps_native_uncertainty(tmp_path: Path, command: str) -> None:
    payload = inspect_command(command, cwd=tmp_path, home_dir=tmp_path)

    assert payload["status"] == "review"
    assert payload["minimum_action"] == "review"
    assert payload["classification"]["action_class"] == "unverified Git remote refresh"
    assert payload["classification"]["explicitly_benign"] is False
    assert payload["controlling_rule_id"] == "command.git.unverified-fetch"


@pytest.fixture(autouse=True)
def _isolate_user_git_config(  # pyright: ignore[reportUnusedFunction]
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home = tmp_path / "git-config-home"
    config = home / ".config"
    config.mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(config))
    for variable in (
        "GIT_CONFIG",
        "GIT_CONFIG_COUNT",
        "GIT_CONFIG_GLOBAL",
        "GIT_CONFIG_NOSYSTEM",
        "GIT_CONFIG_PARAMETERS",
        "GIT_CONFIG_SYSTEM",
        "GIT_COMMON_DIR",
        "GIT_DIR",
        "GIT_NAMESPACE",
        "GIT_WORK_TREE",
    ):
        monkeypatch.delenv(variable, raising=False)


def _repository(tmp_path: Path, *, origin: str = "https://github.com/example/project.git") -> tuple[Path, Path]:
    home = tmp_path / "home"
    repository = home / "projects" / "example"
    repository.mkdir(parents=True)
    _ = subprocess.run(["git", "init", "--quiet", "--initial-branch=main", str(repository)], check=True)
    _ = subprocess.run(["git", "-C", str(repository), "remote", "add", "origin", origin], check=True)
    return home, repository


@pytest.mark.parametrize(
    "command",
    (
        "git -c core.sshCommand=payload fetch origin",
        "git --config-env credential.helper=HELPER fetch origin",
        "git --exec-path=/tmp fetch origin",
    ),
)
def test_execution_config_fetch_keeps_native_uncertainty(tmp_path: Path, command: str) -> None:
    payload = inspect_command(command, cwd=tmp_path, home_dir=tmp_path)

    assert payload["status"] == "review"
    assert payload["minimum_action"] == "review"
    assert payload["classification"]["action_class"] == "unverified Git remote refresh"
    assert payload["classification"]["explicitly_benign"] is False
    assert payload["controlling_rule_id"] == "command.git.unverified-fetch"


def test_url_remote_fetch_retains_unverified_diagnostic_and_native_floor(tmp_path: Path) -> None:
    payload = inspect_command("git fetch https://example.invalid/project.git", cwd=tmp_path, home_dir=tmp_path)

    assert payload["status"] == "review"
    assert payload["minimum_action"] == "review"
    assert payload["classification"]["action_class"] == "unverified Git remote refresh"
    assert payload["controlling_rule_id"] == "command.git.unverified-fetch"
