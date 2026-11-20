from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import codex_plugin_scanner.guard.hook_review.hook_policy_admission as admission


def _bridge(monkeypatch, expected: str) -> None:
    monkeypatch.setattr(admission, "native_policy_not_ready_reason", lambda *args, **kwargs: expected)


def test_native_policy_not_ready_reason_uses_resident_reason(monkeypatch) -> None:
    daemon = SimpleNamespace(
        hook_worker=SimpleNamespace(
            policy_snapshot_publisher=SimpleNamespace(last_error="native_policy_snapshot_runtime_unavailable"),
            guard_home=Path("guard-home"),
        )
    )
    expected = (
        "HOL Guard could not prepare the native policy safely. native_policy_snapshot_runtime_unavailable. "
        "This is usually temporary. Retry this action."
    )
    _bridge(monkeypatch, expected)
    assert admission._native_policy_not_ready_reason(daemon) == expected


def test_native_policy_not_ready_reason_uses_fixed_fallback_without_guard_home() -> None:
    daemon = SimpleNamespace(hook_worker=SimpleNamespace(policy_snapshot_publisher=None))
    assert admission._native_policy_not_ready_reason(daemon) == (
        "HOL Guard could not prepare the native policy safely. This is usually temporary. Retry this action."
    )


def test_native_policy_not_ready_reason_preserves_resident_repair_advice(monkeypatch) -> None:
    daemon = SimpleNamespace(
        hook_worker=SimpleNamespace(
            policy_snapshot_publisher=SimpleNamespace(last_error="native_command_program_binding_mismatch"),
            guard_home=Path("guard-home"),
        )
    )
    reason = (
        "HOL Guard could not prepare the native policy safely. native_command_program_binding_mismatch. "
        "Guard's installed files disagree, so retrying will not clear it. Ask the user to run `hol-guard doctor`."
    )
    _bridge(monkeypatch, reason)
    reason = admission._native_policy_not_ready_reason(daemon)
    assert reason == (
        "HOL Guard could not prepare the native policy safely. native_command_program_binding_mismatch. "
        "Guard's installed files disagree, so retrying will not clear it. Ask the user to run `hol-guard doctor`."
    )
    assert "Retry this action" not in reason


def test_native_policy_not_ready_reason_keeps_repair_advice_when_resident_is_down(monkeypatch) -> None:
    publisher = SimpleNamespace(
        last_error="native_client_timed_out",
        resident_failure_streak=lambda: 4,
    )
    daemon = SimpleNamespace(
        hook_worker=SimpleNamespace(policy_snapshot_publisher=publisher, guard_home=Path("guard-home"))
    )
    monkeypatch.setattr(admission, "native_policy_not_ready_reason", lambda *args, **kwargs: None)

    reason = admission._native_policy_not_ready_reason(daemon)

    assert "hol-guard repair" in reason
    assert "Retry once more" in reason
