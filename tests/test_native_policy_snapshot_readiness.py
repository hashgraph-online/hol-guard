"""Readiness waits stop on failed publication without accepting policy."""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.native_policy_snapshot import NativePolicySnapshotPublisher
from codex_plugin_scanner.guard.store import GuardStore

_FAILURES = (
    "native_policy_snapshot_native_disabled",
    "native_policy_snapshot_runtime_unavailable",
    "native_policy_snapshot_protocol_unsupported",
    "native_policy_snapshot_integrity_key_unavailable",
    "native_policy_snapshot_ack_mismatch",
)


@pytest.mark.parametrize("reason_code", _FAILURES)
def test_readiness_does_not_wait_after_failed_publication(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, reason_code: str
) -> None:
    publisher = NativePolicySnapshotPublisher(store=GuardStore(tmp_path / "guard-home"))
    publisher._record_error(reason_code)

    def unexpected_wait(timeout: float) -> None:
        pytest.fail(f"readiness waited after {reason_code}")

    monkeypatch.setattr(publisher._condition, "wait", unexpected_wait)
    assert not publisher.wait_until_ready(time.monotonic() + 1.0)
    assert publisher.current_snapshot_binding() is None


@pytest.mark.parametrize("reason_code", _FAILURES)
def test_readiness_stops_when_publication_fails_during_wait(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, reason_code: str
) -> None:
    publisher = NativePolicySnapshotPublisher(store=GuardStore(tmp_path / "guard-home"))
    waits = 0

    def report_failure(timeout: float) -> None:
        nonlocal waits
        waits += 1
        if waits > 1:
            pytest.fail(f"readiness resumed waiting after {reason_code}")
        publisher._record_error(reason_code)

    monkeypatch.setattr(publisher._condition, "wait", report_failure)
    assert not publisher.wait_until_ready(time.monotonic() + 1.0)
    assert waits == 1
    assert publisher.current_snapshot_binding() is None


@pytest.mark.parametrize(
    "reason_code", ("native_policy_snapshot_resident_changed", "native_resident_restart_budget_busy")
)
def test_readiness_keeps_waiting_for_transient_resident_recovery(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, reason_code: str
) -> None:
    publisher = NativePolicySnapshotPublisher(store=GuardStore(tmp_path / "guard-home"))
    publisher._record_error(reason_code)

    class WaitingForRecoveryError(Exception):
        pass

    def still_waiting(timeout: float) -> None:
        raise WaitingForRecoveryError

    monkeypatch.setattr(publisher._condition, "wait", still_waiting)
    with pytest.raises(WaitingForRecoveryError):
        publisher.wait_until_ready(time.monotonic() + 1.0)
    assert publisher.current_snapshot_binding() is None
