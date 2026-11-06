from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime.secret_file_requests import (
    extract_sensitive_tool_action_request,
)


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


def _repository(tmp_path: Path) -> tuple[Path, Path]:
    home = tmp_path / "home"
    repository = home / "projects" / "example"
    repository.mkdir(parents=True)
    _ = subprocess.run(["git", "init", "--quiet", "--initial-branch=main", str(repository)], check=True)
    _ = subprocess.run(
        [
            "git",
            "-C",
            str(repository),
            "remote",
            "add",
            "origin",
            "https://github.com/example/project.git",
        ],
        check=True,
    )
    return home, repository


@pytest.mark.parametrize(
    "command",
    (
        "git fetch origin release/2.2",
        "git --no-pager fetch origin release/2.2",
        "git -c credential.helper='!echo pwn' fetch origin release/2.2",
        "/usr/bin/git fetch origin release/2.2",
        "git fetch origin release/2.2; true",
        "true && git fetch origin release/2.2",
        "GIT_DIR=example/.git git fetch origin release/2.2",
        "git --exec-path=/tmp fetch origin release/2.2",
        "git -P fetch origin release/2.2",
        "git -p fetch origin release/2.2",
        "git --no-lazy-fetch fetch origin release/2.2",
        "git --no-optional-locks fetch origin release/2.2",
        "git --no-advice fetch origin release/2.2",
        "git --literal-pathspecs fetch origin release/2.2",
    ),
)
def test_git_fetch_without_repository_bound_cwd_is_sensitive(tmp_path: Path, command: str) -> None:
    home, repository = _repository(tmp_path)
    session_workspace = repository.parent

    request = extract_sensitive_tool_action_request(
        "Bash",
        {"command": command},
        cwd=session_workspace,
        home_dir=home,
    )

    assert request is not None
    if any(marker in command for marker in (" -c ", "--exec-path=", "--config-env", ";", "&&")):
        assert request.action_class == "unverified Git remote refresh"
    else:
        assert request.action_class == "git origin refresh"


def test_git_fetch_without_any_cwd_is_sensitive(tmp_path: Path) -> None:
    request = extract_sensitive_tool_action_request(
        "Bash",
        {"command": "git fetch origin main"},
        cwd=None,
        home_dir=tmp_path,
    )

    assert request is not None
    assert request.action_class == "git origin refresh"
