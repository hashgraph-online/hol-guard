from __future__ import annotations

from types import SimpleNamespace

from codex_plugin_scanner.guard.adapters.cursor_hook_payload import cursor_hook_response_from_guard
from codex_plugin_scanner.guard.daemon.hook_worker_responses import _native_policy_not_ready_reason


def test_cursor_hook_response_surfaces_native_policy_reason() -> None:
    reason = "HOL Guard could not prepare the native policy safely. native_policy_snapshot_runtime_unavailable."
    response = cursor_hook_response_from_guard(
        policy_action="block",
        guard_payload={"reason": reason},
        hook_event_name="beforeShellExecution",
    )
    assert response["permission"] == "deny"
    assert response["user_message"] == reason
    assert response["agent_message"] == reason


def test_cursor_read_deny_surfaces_native_policy_reason() -> None:
    reason = "HOL Guard could not prepare the native policy safely."
    response = cursor_hook_response_from_guard(
        policy_action="block",
        guard_payload={"reason": reason},
        hook_event_name="beforeReadFile",
    )
    assert response["permission"] == "deny"
    assert response["user_message"] == reason
    assert "agent_message" not in response


def test_native_policy_not_ready_reason_includes_publisher_error() -> None:
    daemon = SimpleNamespace(
        hook_worker=SimpleNamespace(
            policy_snapshot_publisher=SimpleNamespace(last_error="native_policy_snapshot_runtime_unavailable")
        )
    )
    assert _native_policy_not_ready_reason(daemon) == (
        "HOL Guard could not prepare the native policy safely. "
        "native_policy_snapshot_runtime_unavailable."
    )
