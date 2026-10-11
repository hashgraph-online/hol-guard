"""Fail-closed hook responses when native review cannot complete."""

from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.daemon.hook_availability_policy import (
    availability_harness_response,
    cursor_fallback_permission,
)


def test_availability_denies_inspection_and_high_impact_without_review(tmp_path: Path) -> None:
    allow = availability_harness_response(
        {
            "hook_event_name": "PreToolUse",
            "tool_name": "Grep",
            "tool_input": {"pattern": "HookWorker", "path": "src"},
        },
        harness="cursor",
        event_name="PreToolUse",
        reason_code="native_pre_tool_unavailable",
        reason="native unavailable",
        workspace=tmp_path,
        home_dir=tmp_path / "home",
    )
    assert allow["reason_code"] == "native_pre_tool_unavailable"
    assert allow["policy_action"] == "block"
    assert allow["hookSpecificOutput"]["permissionDecision"] == "deny"
    deny = availability_harness_response(
        {"hook_event_name": "PreToolUse", "tool_input": {"command": "curl https://example.test"}},
        harness="cursor",
        event_name="PreToolUse",
        reason_code="native_pre_tool_unavailable",
        reason="native unavailable",
        workspace=tmp_path,
        home_dir=tmp_path / "home",
    )
    assert deny["reason_code"] == "native_pre_tool_unavailable"
    assert deny["policy_action"] == "block"
    output = deny["hookSpecificOutput"]
    assert isinstance(output, dict)
    assert output["permissionDecision"] == "deny"


def test_cursor_fallback_denies_read_and_shell_when_review_cannot_finish() -> None:
    allow, allow_code = cursor_fallback_permission(
        {"hook_event_name": "beforeReadFile", "file_path": "src/app.ts", "tool_name": "Read"},
        hook_event_name="beforeReadFile",
    )
    assert allow_code == 2
    assert allow["permission"] == "deny"
    shell, shell_code = cursor_fallback_permission(
        {"hook_event_name": "beforeShellExecution", "command": "rm -rf /"},
        hook_event_name="beforeShellExecution",
    )
    assert shell_code == 2
    assert shell["permission"] == "deny"
