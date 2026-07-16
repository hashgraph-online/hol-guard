"""Focused regressions for specialized structured command variants."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime.command_inspection import inspect_command
from codex_plugin_scanner.guard.runtime.secret_file_requests import extract_sensitive_tool_action_request


@pytest.mark.parametrize(
    "command",
    [
        "git push origin +main",
        "git push origin +refs/heads/main:refs/heads/main",
    ],
)
def test_git_force_push_refspecs_feed_runtime_classification(command: str, tmp_path: Path) -> None:
    payload = inspect_command(command, cwd=tmp_path, home_dir=tmp_path)
    match = extract_sensitive_tool_action_request(
        "Shell",
        {"command": command},
        cwd=tmp_path,
        home_dir=tmp_path,
    )

    assert payload["status"] == "review"
    assert payload["controlling_rule_id"] == "command.git.force-push"
    assert match is not None
    assert match.action_class == "git destructive command"
