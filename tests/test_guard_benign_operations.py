from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime.actions import command_text_from_tool_payload
from codex_plugin_scanner.guard.runtime.secret_file_request_services import shell_static_safety
from codex_plugin_scanner.guard.runtime.secret_file_requests import (
    extract_sensitive_tool_action_request,
    is_explicitly_benign_tool_action_request,
)


def _git(repository: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=repository, check=True, capture_output=True, text=True)


@pytest.fixture
def repository(tmp_path: Path) -> Path:
    path = tmp_path / "repository"
    path.mkdir()
    _git(path, "init", "-q")
    (path / "app.ts").write_text("export const value = 1;\n", encoding="utf-8")
    _git(path, "remote", "add", "origin", "https://github.com/example/project.git")
    return path


def _benign(command: str, *, repository: Path, home: Path) -> bool:
    return is_explicitly_benign_tool_action_request(
        "Bash",
        {"command": command},
        cwd=repository,
        home_dir=home,
    )


def test_mcp_search_query_is_data_but_name_alone_is_not_trust_proof() -> None:
    tool = "mcp__codex_apps__github__search"
    arguments = {"query": "Not publicly verified"}

    assert command_text_from_tool_payload(tool, arguments) is None
    assert extract_sensitive_tool_action_request(tool, arguments) is None
    assert not is_explicitly_benign_tool_action_request(tool, arguments)


def test_mcp_search_preserves_explicit_command_review() -> None:
    tool = "mcp__codex_apps__github__search"
    arguments = {"query": "status", "command": "rm -rf build"}

    assert command_text_from_tool_payload(tool, arguments) == "rm -rf build"
    assert extract_sensitive_tool_action_request(tool, arguments) is not None
    assert not is_explicitly_benign_tool_action_request(tool, arguments)


def test_guard_status_native_name_is_unverified_but_cli_is_benign(
    repository: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert not is_explicitly_benign_tool_action_request(
        "mcp__codex_apps__hol_guard__get_guard_status",
        {},
        cwd=repository,
        home_dir=tmp_path,
    )
    executable = tmp_path / "bin" / "hol-guard"
    executable.parent.mkdir()
    executable.write_text("#!/bin/sh\n", encoding="utf-8")
    monkeypatch.setattr(sys, "prefix", str(tmp_path))
    monkeypatch.setattr(
        shell_static_safety,
        "_which_for_execution_cwd",
        lambda *_args, **_kwargs: str(executable),
    )

    assert _benign("hol-guard status", repository=repository, home=tmp_path)


@pytest.mark.parametrize(
    "command",
    (
        "git fetch origin --quiet",
        "git log -1 --format='%H %cI %s' origin/main",
        "git blame -L 1,1 -- app.ts",
        "git show HEAD~1:app.ts | sed -n '1,55p'",
    ),
)
def test_bounded_git_operations_are_benign(repository: Path, tmp_path: Path, command: str) -> None:
    assert _benign(command, repository=repository, home=tmp_path)


@pytest.mark.parametrize(
    "command",
    (
        "git fetch origin --force",
        "git log -1 --format='%x00' origin/main",
        "git blame -L 1,999999 -- app.ts",
        "git blame -L 1,1 -- ../outside.ts",
        "git show HEAD~99999:app.ts | sed -n '1,55p'",
    ),
)
def test_bounded_git_operations_reject_widening(repository: Path, tmp_path: Path, command: str) -> None:
    assert not _benign(command, repository=repository, home=tmp_path)


@pytest.mark.parametrize(
    ("key", "value"),
    (
        ("pager.blame", "sh payload.sh"),
        ("diff.guard.textconv", "sh payload.sh"),
    ),
)
def test_git_blame_rejects_executable_repository_config(
    repository: Path,
    tmp_path: Path,
    key: str,
    value: str,
) -> None:
    _git(repository, "config", key, value)

    assert not _benign("git blame -L 1,1 -- app.ts", repository=repository, home=tmp_path)


def test_guard_safety_doc_is_a_read_only_source(tmp_path: Path, repository: Path) -> None:
    support = tmp_path / ".hol-support"
    support.mkdir()
    (support / "SAFETY.md").write_text("# Safety\n", encoding="utf-8")

    assert _benign("sed -n '1,220p' ~/.hol-support/SAFETY.md", repository=repository, home=tmp_path)
