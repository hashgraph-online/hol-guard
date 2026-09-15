from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.cli.commands_support_runtime_artifacts import _hook_runtime_artifact
from codex_plugin_scanner.guard.runtime.secret_file_requests import extract_sensitive_tool_action_request


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
    "repository_operand",
    (
        "'~/projects/example'",
        '"~/projects/example"',
        r"\~/projects/example",
    ),
)
def test_home_git_c_fetch_accepts_quoted_or_escaped_tilde_path(
    tmp_path: Path,
    repository_operand: str,
) -> None:
    home, _repository_path = _repository(tmp_path)
    workspace = home / "workspace"
    workspace.mkdir()
    command = f"git -C {repository_operand} fetch origin release/3.0"

    assert extract_sensitive_tool_action_request(
        "Bash",
        {"command": command},
        cwd=workspace,
        home_dir=home,
    ) is None


def test_home_git_c_fetch_accepts_absolute_path_from_sibling_workspace(tmp_path: Path) -> None:
    home, repository = _repository(tmp_path)
    workspace = home / "workspace"
    workspace.mkdir()
    command = f"git -C {repository} fetch origin release/3.0"

    assert extract_sensitive_tool_action_request(
        "Bash",
        {"command": command},
        cwd=workspace,
        home_dir=home,
    ) is None
    assert (
        _hook_runtime_artifact(
            harness="codex",
            payload={
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "tool_input": {"command": command},
                "cwd": str(workspace),
            },
            action_envelope=None,
            home_dir=home,
            guard_home=home / ".guard",
            workspace=workspace,
        )
        is None
    )
