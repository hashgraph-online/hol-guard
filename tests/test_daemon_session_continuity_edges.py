"""Session-continuity edges when native review cannot finish or PostTool blocks."""

from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.adapters.bounded_cli_hook_failure import failure_payload
from codex_plugin_scanner.guard.adapters.cline_bridge import plugin_after_tool_replacement
from codex_plugin_scanner.guard.cli.commands_support_runtime_resolution import (
    _is_copilot_permission_request,
)
from codex_plugin_scanner.guard.daemon.hook_availability_policy import (
    availability_harness_response,
    cursor_unparseable_input_permission,
    hook_event_is_permission_request,
)
from codex_plugin_scanner.guard.daemon.hook_request_parsing import runtime_hook_event_name
from codex_plugin_scanner.guard.daemon.hook_worker_responses import (
    post_tool_fail_safe_response,
    post_tool_native_block_response,
)


def test_permission_denied_lifecycle_is_not_canonicalized_to_permission_request() -> None:
    assert runtime_hook_event_name({"hook_event_name": "PermissionDenied"}) == "PermissionDenied"
    assert runtime_hook_event_name({"hook_name": "permissionRequestV2"}) == "PermissionRequest"
    denied = availability_harness_response(
        {"hook_event_name": "PermissionDenied"},
        harness="claude-code",
        event_name="PermissionDenied",
        reason_code="native_hook_event_unavailable",
        reason="native unavailable",
    )
    assert denied["continue"] is True


def test_cline_after_tool_transport_miss_passes_through_original_result() -> None:
    assert plugin_after_tool_replacement("") is None
    assert plugin_after_tool_replacement("not json") is None
    blocked = plugin_after_tool_replacement('{"decision":"block","reason":"secret"}')
    assert blocked is not None
    assert blocked["result"]["isError"] is True


def test_post_tool_fail_safe_continues_the_turn() -> None:
    payload = post_tool_fail_safe_response("claude-code", reason="worker exploded")
    assert payload["continue"] is True
    assert payload.get("decision") != "block"


def test_successful_post_tool_block_withholds_without_stopping() -> None:
    payload = post_tool_native_block_response(reason="credential-looking output")
    assert payload["decision"] == "block"
    assert payload["model_output_action"] == "block"
    assert payload["continue"] is True
    assert payload["hookSpecificOutput"]["additionalContext"] == "credential-looking output"


def test_old_cursor_hooks_allow_empty_stdin_without_baked_event() -> None:
    allow, code = cursor_unparseable_input_permission("")
    assert code == 0
    assert allow == {"permission": "allow"}
    deny, deny_code = cursor_unparseable_input_permission("beforeShellExecution")
    assert deny_code == 2
    assert deny["permission"] == "deny"


def test_native_off_pretool_continues_without_watch(tmp_path: Path) -> None:
    payload = availability_harness_response(
        {"hook_event_name": "PreToolUse", "tool_input": {"command": "curl https://example.test"}},
        harness="grok",
        event_name="PreToolUse",
        reason_code="native_hook_disabled",
        reason="native off",
        workspace=tmp_path,
        home_dir=tmp_path / "home",
    )
    assert payload["decision"] == "allow"
    permission = availability_harness_response(
        {"hook_event_name": "PermissionRequest"},
        harness="claude-code",
        event_name="PermissionRequest",
        reason_code="native_hook_disabled",
        reason="native off",
    )
    assert permission["continue"] is True
    daemon_miss = availability_harness_response(
        {"hook_event_name": "PreToolUse", "tool_input": {"command": "curl https://example.test"}},
        harness="grok",
        event_name="PreToolUse",
        reason_code="native_pre_tool_unavailable",
        reason="native unavailable",
        workspace=tmp_path,
        home_dir=tmp_path / "home",
    )
    assert daemon_miss["decision"] == "allow"


def test_native_policy_not_ready_pretool_continues(tmp_path: Path) -> None:
    payload = availability_harness_response(
        {"hook_event_name": "PreToolUse", "tool_input": {"command": "curl https://example.test"}},
        harness="claude-code",
        event_name="PreToolUse",
        reason_code="native_policy_not_ready",
        reason="native policy was not ready",
        workspace=tmp_path,
        home_dir=tmp_path / "home",
    )
    assert payload["continue"] is True
    assert payload["hookSpecificOutput"]["permissionDecision"] == "allow"


def test_cursor_write_continues_when_native_unavailable() -> None:
    from codex_plugin_scanner.guard.daemon.hook_availability_policy import cursor_fallback_permission

    allow, code = cursor_fallback_permission(
        {"hook_event_name": "beforeWriteFile", "file_path": "src/app.ts", "tool_name": "Write"},
        hook_event_name="beforeWriteFile",
    )
    assert code == 0
    assert allow == {"permission": "allow"}


def test_copilot_permission_request_v2_uses_behavior_deny_shape() -> None:
    assert _is_copilot_permission_request({"hook_name": "permissionRequestV2"}) is True
    assert _is_copilot_permission_request({"hookEventName": "PermissionRequestV2"}) is True
    assert _is_copilot_permission_request({"hook_name": "copilotPermissionRequest"}) is True
    assert _is_copilot_permission_request({"hook_name": "PermissionDenied"}) is False
    assert _is_copilot_permission_request({"hook_name": "PermissionResponse"}) is False
    assert hook_event_is_permission_request("copilotPermissionRequest") is True
    assert hook_event_is_permission_request("PermissionDenied") is False
    assert hook_event_is_permission_request("PermissionRequestFoo") is False
    camel, camel_code = failure_payload(
        harness="copilot",
        event_name="permissionRequestV2",
        reason="native unavailable",
        payload={"hook_name": "permissionRequestV2"},
        recording_only=False,
    )
    assert camel_code == 0
    assert camel["behavior"] == "deny"
    assert camel["interrupt"] is False
    payload, code = failure_payload(
        harness="copilot",
        event_name="PermissionRequestV2",
        reason="native unavailable",
        payload={"hook_event_name": "PermissionRequestV2"},
        recording_only=False,
    )
    assert code == 0
    assert payload["behavior"] == "deny"
    assert payload["interrupt"] is False
    assert "permissionDecision" not in payload
    availability = availability_harness_response(
        {"hook_event_name": "PermissionRequestV2"},
        harness="copilot",
        event_name="PermissionRequestV2",
        reason_code="native_hook_event_unavailable",
        reason="native unavailable",
    )
    assert availability["behavior"] == "deny"
    assert availability["interrupt"] is False
