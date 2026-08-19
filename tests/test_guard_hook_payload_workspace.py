from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.cli.commands_support_workspace import _workspace_from_hook_payload
from codex_plugin_scanner.guard.runtime.secret_file_requests import is_explicitly_benign_tool_action_request


@pytest.fixture(autouse=True)
def _isolate_git_config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home = tmp_path / "git-config-home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(home / "config"))
    for variable in ("GIT_CONFIG", "GIT_CONFIG_GLOBAL", "GIT_EXTERNAL_DIFF"):
        monkeypatch.delenv(variable, raising=False)


def _repository(root: Path) -> Path:
    repository = root / "project"
    repository.mkdir()
    _ = subprocess.run(["git", "init", "--quiet", "--initial-branch=main", str(repository)], check=True)
    return repository


def test_hook_payload_cwd_resolves_workspace(tmp_path: Path) -> None:
    repository = _repository(tmp_path)

    assert _workspace_from_hook_payload({"cwd": str(repository)}) == repository.resolve()
    assert _workspace_from_hook_payload({"workspaceRoot": str(repository)}) == repository.resolve()
    assert _workspace_from_hook_payload({}) is None


def test_cached_check_is_benign_only_with_payload_cwd(tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir()
    repository = _repository(tmp_path)
    command = {"command": "git diff --cached --check"}

    assert not is_explicitly_benign_tool_action_request("Bash", command, cwd=None, home_dir=home)
    assert is_explicitly_benign_tool_action_request("Bash", command, cwd=repository, home_dir=home)
