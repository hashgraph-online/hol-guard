from __future__ import annotations

from codex_plugin_scanner.guard.daemon.hook_worker_responses import (
    integrity_fail_closed_hook_response,
)


def test_integrity_refusal_uses_permission_request_shape_for_codex() -> None:
    result = integrity_fail_closed_hook_response(
        "codex",
        event_name="PermissionRequest",
        reason="Policy authority is unavailable.",
        reason_code="native_scoped_authority_unavailable",
    )
    output = result["hookSpecificOutput"]
    assert isinstance(output, dict)
    assert output["hookEventName"] == "PermissionRequest"
    decision = output["decision"]
    assert isinstance(decision, dict)
    assert decision["behavior"] == "deny"
    assert decision["message"] == "Policy authority is unavailable."
    assert "permissionDecision" not in output


def test_integrity_refusal_uses_copilot_permission_contract() -> None:
    result = integrity_fail_closed_hook_response(
        "copilot",
        event_name="PermissionRequest",
        reason="Policy authority is unavailable.",
        reason_code="native_scoped_authority_unavailable",
    )
    assert result == {
        "behavior": "deny",
        "message": "Policy authority is unavailable.",
        "interrupt": False,
        "reason_code": "native_scoped_authority_unavailable",
    }
