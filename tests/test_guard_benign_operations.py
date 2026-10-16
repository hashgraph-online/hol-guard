from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime.secret_file_request_services import shell_static_safety
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


def _trust_guard_executable(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    executable_directory = "Scripts" if sys.platform == "win32" else "bin"
    executable_name = "hol-guard.exe" if sys.platform == "win32" else "hol-guard"
    executable = tmp_path / executable_directory / executable_name
    executable.parent.mkdir()
    _ = executable.write_text("#!/bin/sh\n", encoding="utf-8")
    monkeypatch.setattr(sys, "prefix", str(tmp_path))

    def trusted_guard_path(_command: str, *, cwd: Path) -> str:
        _ = cwd
        return str(executable)

    monkeypatch.setattr(
        shell_static_safety,
        "_which_for_execution_cwd",
        trusted_guard_path,
    )


def test_non_shell_tool_text_is_not_interpreted_as_a_command() -> None:
    arguments = {
        "items": ["PR verified and all checks are green."],
        "op": "append",
        "phase": "review",
    }

    assert extract_sensitive_tool_action_request("todo", arguments) is None
    assert extract_sensitive_tool_action_request("todo", {"command": "rm -rf build"}) is not None
