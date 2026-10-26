from __future__ import annotations

from types import SimpleNamespace

from codex_plugin_scanner.guard.daemon.hook_policy_admission import _native_policy_not_ready_reason


def test_installed_cursor_hook_script_includes_approval_url_copy() -> None:
    from codex_plugin_scanner.guard.adapters.cursor_hooks import _HOOK_SCRIPT_TEMPLATE

    assert "def _cursor_reason(" in _HOOK_SCRIPT_TEMPLATE
    assert "Open HOL Guard to approve or keep this blocked: " in _HOOK_SCRIPT_TEMPLATE
    assert "primary_approval_url" in _HOOK_SCRIPT_TEMPLATE
    assert "live_approval_review_url" in _HOOK_SCRIPT_TEMPLATE


def test_native_policy_not_ready_reason_includes_publisher_error() -> None:
    daemon = SimpleNamespace(
        hook_worker=SimpleNamespace(
            policy_snapshot_publisher=SimpleNamespace(last_error="native_policy_snapshot_runtime_unavailable")
        )
    )
    assert _native_policy_not_ready_reason(daemon) == (
        "HOL Guard could not prepare the native policy safely. native_policy_snapshot_runtime_unavailable. "
        "This is usually temporary. Retry this action."
    )


def test_native_policy_not_ready_reason_asks_for_a_retry_without_a_publisher_error() -> None:
    daemon = SimpleNamespace(hook_worker=SimpleNamespace(policy_snapshot_publisher=None))
    assert _native_policy_not_ready_reason(daemon) == (
        "HOL Guard could not prepare the native policy safely. This is usually temporary. Retry this action."
    )


def test_native_policy_not_ready_reason_names_a_repair_for_a_mismatched_install() -> None:
    daemon = SimpleNamespace(
        hook_worker=SimpleNamespace(
            policy_snapshot_publisher=SimpleNamespace(last_error="native_command_program_binding_mismatch")
        )
    )
    reason = _native_policy_not_ready_reason(daemon)
    assert reason == (
        "HOL Guard could not prepare the native policy safely. native_command_program_binding_mismatch. "
        "Guard's installed files disagree, so retrying will not clear it. Ask the user to run `hol-guard doctor`."
    )
    assert "Retry this action" not in reason
