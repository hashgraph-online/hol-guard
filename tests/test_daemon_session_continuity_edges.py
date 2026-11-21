"""Session-continuity edges when native review cannot finish or PostTool blocks."""

from __future__ import annotations

import json
from pathlib import Path

from codex_plugin_scanner.guard.hook_review.hook_availability_policy import (
    availability_harness_response,
    canonical_hook_event_name,
    cursor_unparseable_input_permission,
    hook_event_is_permission_request,
)


def test_permission_denied_lifecycle_is_not_canonicalized_to_permission_request() -> None:
    assert canonical_hook_event_name({"hook_event_name": "PermissionDenied"}) == "PermissionDenied"
    assert canonical_hook_event_name({"hook_name": "permissionRequestV2"}) == "PermissionRequest"
    denied = availability_harness_response(
        harness="claude-code",
        event_name="PermissionDenied",
        reason_code="native_hook_event_unavailable",
        reason="native unavailable",
    )
    assert denied["continue"] is True


def test_old_cursor_hooks_deny_empty_stdin_without_baked_event() -> None:
    allow, code = cursor_unparseable_input_permission("")
    assert code == 2
    assert allow["permission"] == "deny"
    deny, deny_code = cursor_unparseable_input_permission("beforeShellExecution")
    assert deny_code == 2
    assert deny["permission"] == "deny"


def test_native_unavailable_pretool_denies_without_watch(tmp_path: Path) -> None:
    payload = availability_harness_response(
        harness="grok",
        event_name="PreToolUse",
        reason_code="native_pre_tool_unavailable",
        reason="native unavailable",
    )
    assert payload["decision"] == "deny"
    permission = availability_harness_response(
        harness="claude-code",
        event_name="PermissionRequest",
        reason_code="native_pre_tool_unavailable",
        reason="native unavailable",
    )
    assert permission["hookSpecificOutput"]["decision"]["behavior"] == "deny"
    daemon_miss = availability_harness_response(
        harness="grok",
        event_name="PreToolUse",
        reason_code="native_pre_tool_unavailable",
        reason="native unavailable",
    )
    assert daemon_miss["decision"] == "deny"


def test_native_policy_not_ready_pretool_denies_without_interrupting_session(tmp_path: Path) -> None:
    payload = availability_harness_response(
        harness="claude-code",
        event_name="PreToolUse",
        reason_code="native_policy_not_ready",
        reason="native policy was not ready",
    )
    assert payload.get("continue") is not False
    assert payload["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_cursor_write_denies_when_native_unavailable() -> None:
    from codex_plugin_scanner.guard.hook_review.hook_availability_policy import cursor_fallback_permission

    deny, code = cursor_fallback_permission(
        hook_event_name="beforeWriteFile",
    )
    assert code == 2
    assert deny["permission"] == "deny"
    assert deny["agent_message"] == deny["user_message"]


def test_copilot_permission_request_v2_uses_behavior_deny_shape() -> None:
    assert hook_event_is_permission_request("permissionRequestV2") is True
    assert hook_event_is_permission_request("PermissionRequestV2") is True
    assert hook_event_is_permission_request("PermissionResponse") is False
    assert hook_event_is_permission_request("copilotPermissionRequest") is True
    assert hook_event_is_permission_request("PermissionDenied") is False
    assert hook_event_is_permission_request("PermissionRequestFoo") is False
    availability = availability_harness_response(
        harness="copilot",
        event_name="PermissionRequestV2",
        reason_code="native_hook_event_unavailable",
        reason="native unavailable",
    )
    assert availability["behavior"] == "deny"
    assert availability["interrupt"] is False


def test_missing_native_fail_safe_codes_continue_mutating_pretool(tmp_path: Path) -> None:
    reason = "HOL Guard could not complete the native hook decision safely."
    for reason_code in (
        "native_hook_edge_invalid_response",
        "native_hook_compatibility_disabled",
        "native_hook_worker_unavailable_before_compatibility",
        "python_hook_oracle_unavailable",
        "harness_not_managed",
        "native_degraded_emergency_safe",
        "unlisted_native_miss",
    ):
        response = availability_harness_response(
            harness="cursor",
            event_name="PreToolUse",
            reason_code=reason_code,
            reason=reason,
        )
        output = response["hookSpecificOutput"]
        assert isinstance(output, dict)
        assert output["permissionDecision"] == "deny"
        assert response["policy_action"] == "block"


def test_cursor_maps_before_write_file_to_a_write_pretooluse() -> None:
    from tests.cursor_hook_payload_support import prepare_cursor_hook_payload

    mapped = prepare_cursor_hook_payload(
        {"hook_event_name": "beforeWriteFile", "file_path": "src/app.ts", "tool_name": "Read"}
    )
    assert mapped["hook_event_name"] == "PreToolUse"
    assert mapped["tool_name"] == "Write"


def test_invalid_hook_payload_reference_stays_fail_closed(tmp_path: Path) -> None:
    response = availability_harness_response(
        harness="cursor",
        event_name="PreToolUse",
        reason_code="invalid_hook_payload_reference",
        reason="HOL Guard could not authenticate the local hook payload.",
    )
    output = response["hookSpecificOutput"]
    assert isinstance(output, dict)
    assert output["permissionDecision"] == "deny"
    assert response["policy_action"] == "block"


def test_retained_byte_limit_stays_fail_closed(tmp_path: Path) -> None:
    response = availability_harness_response(
        harness="pi",
        event_name="PreToolUse",
        reason_code="daemon_hook_queue_bytes",
        reason="HOL Guard rejected this hook because the payload exceeded the retained-byte limit.",
    )
    assert response["decision"] == "deny"
    assert response["policy_action"] == "block"


def test_queue_byte_limit_denies_unverified_repair(tmp_path: Path) -> None:
    response = availability_harness_response(
        harness="claude-code",
        event_name="PreToolUse",
        reason_code="daemon_hook_queue_bytes",
        reason="HOL Guard rejected this hook because the payload exceeded the retained-byte limit.",
    )
    assert response.get("policy_action") == "block"
    output = response["hookSpecificOutput"]
    assert isinstance(output, dict)
    assert output.get("permissionDecision") == "deny"


def test_invalid_payload_reference_still_denies_a_repair_command(tmp_path: Path) -> None:
    response = availability_harness_response(
        harness="cursor",
        event_name="PreToolUse",
        reason_code="invalid_hook_payload_reference",
        reason="HOL Guard could not authenticate the local hook payload.",
    )
    output = response["hookSpecificOutput"]
    assert isinstance(output, dict)
    assert output["permissionDecision"] == "deny"
    assert response["policy_action"] == "block"


def test_bounded_cli_cannot_finish_without_policy_action_denies_write(native_bridge_render) -> None:

    stdout, _stderr, code = native_bridge_render(
        {"reason_code": "native_pre_tool_unavailable", "reason": "native miss"},
        harness="kimi",
        event_name="PreToolUse",
    )
    payload = json.loads(stdout)
    assert code == 2
    assert payload["hookSpecificOutput"]["permissionDecision"] == "deny"
    invalid_stdout, _invalid_stderr, invalid_code = native_bridge_render(
        {"policy_action": "invalid", "reason": "nope"},
        harness="kimi",
        event_name="PreToolUse",
    )
    assert invalid_code == 2
    assert json.loads(invalid_stdout)["hookSpecificOutput"]["permissionDecision"] == "deny"
