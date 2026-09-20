"""Current delivered responses stay distinct from evaluation and provenance.

These controls call production renderers. They do not claim native execution,
installed-harness delivery, receipt persistence, or approval consumption.
"""

from __future__ import annotations

from copy import deepcopy

import pytest

from codex_plugin_scanner.guard.daemon.hook_availability_policy import (
    availability_harness_response,
    cursor_fallback_permission,
    cursor_unparseable_input_permission,
)
from codex_plugin_scanner.guard.daemon.hook_worker_native import (
    _watch_native_post_tool_result,
    _watch_native_pre_tool_result,
)
from codex_plugin_scanner.guard.daemon.hook_worker_responses import (
    harness_json_from_native_post_tool,
    harness_json_from_native_pre_tool,
)
from codex_plugin_scanner.guard.native_route_receipt import (
    native_hook_route,
    record_native_hook_result,
    reset_native_hook_route,
)


@pytest.mark.parametrize("recording_only", [False, True], ids=["enforce", "watch"])
@pytest.mark.parametrize("harness", ["claude-code", "grok", "cursor"])
@pytest.mark.parametrize(
    "reason_code",
    [
        "native_policy_not_ready",
        "native_hook_edge_invalid_response",
        "native_command_control_fence_unavailable",
        "daemon_hook_deadline_exhausted",
    ],
)
def test_unavailability_warns_without_creating_native_success(harness, reason_code, recording_only):
    # High-impact input is intentionally outside the emergency-safe profile.
    payload = {"hook_event_name": "PreToolUse", "tool_input": {"command": "rm -rf ./worktree"}}
    original = deepcopy(payload)
    reset_native_hook_route()
    try:
        assert record_native_hook_result("native_fail_safe", None) is None
        response = availability_harness_response(
            payload,
            harness=harness,
            event_name="PreToolUse",
            reason_code=reason_code,
            reason="review unavailable",
            recording_only=recording_only,
        )
        assert response["policy_action"] == "warn"
        assert response["reason_code"] == reason_code
        if harness == "grok":
            assert response["decision"] == "allow"
        else:
            assert response["continue"] is True
            hook_output = response["hookSpecificOutput"]
            assert isinstance(hook_output, dict)
            assert hook_output["permissionDecision"] == "allow"
        assert native_hook_route() == "native_fail_safe"
        assert "receipt" not in response
        assert payload == original
    finally:
        reset_native_hook_route()


@pytest.mark.parametrize("recording_only", [False, True], ids=["enforce", "watch"])
@pytest.mark.parametrize("harness,decision", [("claude-code", "deny"), ("hermes", "block"), ("pi", "deny")])
@pytest.mark.parametrize("reason_code", ["invalid_hook_payload_reference", "daemon_hook_queue_bytes"])
def test_integrity_rejection_still_denies_in_both_postures(harness, decision, reason_code, recording_only):
    response = availability_harness_response(
        {"hook_event_name": "beforeShellExecution", "command": "pwd"},
        harness=harness,
        event_name="beforeShellExecution",
        reason_code=reason_code,
        reason="integrity rejection",
        recording_only=recording_only,
    )
    assert response["policy_action"] == "block"
    assert response["reason_code"] == reason_code
    if harness == "claude-code":
        hook_output = response["hookSpecificOutput"]
        assert isinstance(hook_output, dict)
        assert hook_output["permissionDecision"] == decision
    else:
        assert response["decision"] == decision


@pytest.mark.parametrize("harness", ["claude-code", "grok", "pi"])
def test_posttool_unavailability_and_completed_block_are_different(harness):
    unavailable = availability_harness_response(
        {"hook_event_name": "PostToolUse"},
        harness=harness,
        event_name="PostToolUse",
        reason_code="native_post_tool_unavailable",
        reason="review unavailable",
    )
    native_block = {
        "decision": "block",
        "model_output_action": "block",
        "policy_action": "block",
        "reason_code": "independent_secret_floor",
        "reason": "blocked output",
    }
    blocked = harness_json_from_native_post_tool(harness, native_block)
    assert blocked["decision"] == blocked["model_output_action"] == "block"
    assert blocked["policy_action"] == "block"
    if harness == "grok":
        assert unavailable == {}
    elif harness == "pi":
        assert unavailable["decision"] == "allow"
    else:
        assert unavailable["continue"] is True
        # Conversation continuation alone cannot distinguish output release.
        assert blocked["continue"] is True
    assert unavailable != blocked


@pytest.mark.parametrize("harness", ["copilot", "claude-code", "hermes", "pi"])
def test_permission_availability_does_not_invent_an_approval(harness):
    response = availability_harness_response(
        {"hook_event_name": "PermissionRequest", "tool_input": {"command": "pwd"}},
        harness=harness,
        event_name="PermissionRequest",
        reason_code="native_hook_event_unavailable",
        reason="review unavailable",
    )
    if harness == "copilot":
        assert response["behavior"] == "deny"
        assert response["interrupt"] is False
    elif harness == "claude-code":
        assert response["continue"] is True
        assert response["hookSpecificOutput"] == {"hookEventName": "PermissionRequest"}
    else:
        assert response["decision"] == "allow"
    assert response["reason_code"] == "native_hook_event_unavailable"
    assert "approval_reuse_status" not in response
    assert "approval_request_id" not in response


@pytest.mark.parametrize("event", ["beforeShellExecution", "beforeMCPExecution"])
def test_cursor_unavailable_and_malformed_input_keep_distinct_contracts(event):
    allowed, allow_code = cursor_fallback_permission({"command": "rm -rf ./worktree"}, hook_event_name=event)
    denied, deny_code = cursor_unparseable_input_permission(event)
    observed, observe_code = cursor_unparseable_input_permission(event, recording_only=True)
    assert (allowed, allow_code) == ({"permission": "allow"}, 0)
    assert denied["permission"] == "deny"
    assert deny_code == 2
    assert (observed, observe_code) == ({"permission": "allow"}, 0)


def test_watch_copy_does_not_rewrite_the_native_block():
    native_pre = {"decision": "deny", "minimum_action": "block", "reason_code": "independent_floor"}
    native_post = {
        "decision": "block",
        "model_output_action": "block",
        "policy_action": "block",
        "reason_code": "independent_secret_floor",
    }
    original_pre, original_post = deepcopy(native_pre), deepcopy(native_post)
    watched_pre = _watch_native_pre_tool_result(native_pre)
    watched_post = _watch_native_post_tool_result(native_post, {})
    assert native_pre == original_pre
    assert native_post == original_post
    assert watched_pre is not native_pre and watched_post is not native_post
    assert watched_pre["decision"] == watched_post["decision"] == "allow"
    assert watched_pre["policy_action"] == watched_post["policy_action"] == "warn"
    delivered_pre = harness_json_from_native_pre_tool("claude-code", watched_pre)
    delivered_post = harness_json_from_native_post_tool("claude-code", watched_post)
    hook_output = delivered_pre["hookSpecificOutput"]
    assert isinstance(hook_output, dict)
    assert hook_output["permissionDecision"] == "allow"
    assert delivered_post["policy_action"] == "warn"
    assert "reviewed_output_sha256" not in watched_post
