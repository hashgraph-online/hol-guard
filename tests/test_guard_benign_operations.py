from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime.secret_file_requests import (
    extract_sensitive_tool_action_request,
)


def _git(repository: Path, *args: str) -> None:
    _ = subprocess.run(["git", *args], cwd=repository, check=True, capture_output=True, text=True)


@pytest.fixture
def repository(tmp_path: Path) -> Path:
    path = tmp_path / "repository"
    path.mkdir()
    _git(path, "init", "-q")
    _ = (path / "app.ts").write_text("export const value = 1;\n", encoding="utf-8")
    _git(path, "remote", "add", "origin", "https://github.com/example/project.git")
    return path


def test_non_shell_tool_text_is_not_interpreted_as_a_command() -> None:
    arguments = {
        "items": ["PR verified and all checks are green."],
        "op": "append",
        "phase": "review",
    }

    assert extract_sensitive_tool_action_request("todo", arguments) is None
    assert extract_sensitive_tool_action_request("todo", {"command": "rm -rf build"}) is not None
