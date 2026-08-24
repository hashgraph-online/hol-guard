"""Focused Phase 8 continuation-contract tests, independent of Cloud transport."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from threading import Event
from time import monotonic, sleep

import pytest

from codex_plugin_scanner.guard.continuation_contract import (
    ContinuationCoordinator,
    ContinuationOffer,
    ContinuationResult,
    capability_offer,
)

CORRELATION_ID = "gcrv2_018f0a0a-1234-7abc-8def-0123456789ab"
NOW = datetime(2026, 8, 24, tzinfo=timezone.utc)


class FakeAdapter:
    def __init__(self) -> None:
        self.calls: int = 0

    def continue_after_application(
        self, offer: ContinuationOffer, *, action: str, timeout_seconds: float, cancelled: object
    ) -> ContinuationResult:
        self.calls += 1
        assert action == "allow_once"
        assert timeout_seconds == 3
        assert callable(cancelled)
        return ContinuationResult(
            correlation_id=offer.correlation_id,
            capability=offer.capability,
            status="resumed",
            reason="live_hook_response_accepted",
            completed_at=NOW,
            evidence_id="evidence-codex-hook-0001",
        )


def test_codex_live_hook_is_the_only_suspended_response_offer() -> None:
    live = capability_offer(
        correlation_id=CORRELATION_ID,
        harness="codex",
        original_hook_attached=True,
        wait_deadline=NOW + timedelta(seconds=30),
        now=lambda: NOW,
    )
    assert live.capability == "suspended-response"
    assert live.original_hook_attached is True

    expired = capability_offer(
        correlation_id=CORRELATION_ID,
        harness="codex",
        original_hook_attached=True,
        wait_deadline=NOW - timedelta(seconds=1),
        now=lambda: NOW,
    )
    assert expired.capability == "retry-only"


def test_headless_codex_never_claims_session_resume() -> None:
    offer = capability_offer(
        correlation_id=CORRELATION_ID,
        harness="codex",
        original_hook_attached=False,
        wait_deadline=None,
        opaque_target_id="codex-thread-opaque-01",
        session_target_verified=True,
        headless=True,
    )
    assert offer.capability == "retry-only"
    assert offer.opaque_target_id is None


@pytest.mark.parametrize("harness", ["pi", "omp", "oh-my-pi", "grok", "openclaw", "hermes"])
def test_unproven_harnesses_explicitly_downgrade_to_retry_only(harness: str) -> None:
    offer = capability_offer(
        correlation_id=CORRELATION_ID,
        harness=harness,
        original_hook_attached=False,
        wait_deadline=None,
    )
    assert offer.capability == "retry-only"


def test_coordinator_records_terminal_evidence_once_and_notifies_manual_retry() -> None:
    offer = capability_offer(
        correlation_id=CORRELATION_ID,
        harness="pi",
        original_hook_attached=False,
        wait_deadline=None,
    )
    attempts: list[ContinuationResult] = []
    notifications: list[ContinuationResult] = []
    adapter = FakeAdapter()
    coordinator = ContinuationCoordinator(
        adapter,
        record_attempt=lambda _offer, _action, result: attempts.append(result),
        notify_manual_retry=lambda _offer, result: notifications.append(result),
        now=lambda: NOW,
    )

    first = coordinator.continue_after_application(offer, action="allow_once", timeout_seconds=3)
    second = coordinator.continue_after_application(offer, action="allow_once", timeout_seconds=3)

    assert first is second
    assert first.status == "manual_retry_required"
    assert adapter.calls == 0
    assert attempts == [first]
    assert notifications == [first]


def test_coordinator_proves_live_hook_and_rejects_invalid_opaque_target() -> None:
    adapter = FakeAdapter()
    attempts: list[ContinuationResult] = []
    coordinator = ContinuationCoordinator(
        adapter,
        record_attempt=lambda _offer, _action, result: attempts.append(result),
        notify_manual_retry=lambda _offer, _result: None,
        now=lambda: NOW,
    )
    offer = ContinuationOffer(
        correlation_id=CORRELATION_ID,
        harness="codex",
        capability="suspended-response",
        original_hook_attached=True,
        wait_deadline=NOW + timedelta(seconds=10),
    )
    result = coordinator.continue_after_application(offer, action="allow_once", timeout_seconds=3)
    assert result.status == "resumed"
    assert attempts == [result]
    assert adapter.calls == 1

    with pytest.raises(ValueError, match="safe opaque"):
        _ = ContinuationOffer(
            correlation_id=CORRELATION_ID,
            harness="codex",
            capability="session-resume",
            original_hook_attached=False,
            opaque_target_id="raw socket path",
        )


def test_bounded_adapter_cancels_a_hung_worker_and_records_timeout() -> None:
    class HangingAdapter:
        def __init__(self) -> None:
            self.cancelled = Event()

        def continue_after_application(
            self, offer: ContinuationOffer, *, action: str, timeout_seconds: float, cancelled: object
        ) -> ContinuationResult:
            assert callable(cancelled)
            while not cancelled():
                sleep(0.001)
            self.cancelled.set()
            return ContinuationResult(
                correlation_id=offer.correlation_id,
                capability=offer.capability,
                status="failed",
                reason="worker_cancelled",
                completed_at=NOW,
                evidence_id="evidence-hung-worker-0001",
            )

    adapter = HangingAdapter()
    attempts: list[ContinuationResult] = []
    coordinator = ContinuationCoordinator(
        adapter,
        record_attempt=lambda _offer, _action, result: attempts.append(result),
        notify_manual_retry=lambda _offer, _result: None,
        now=lambda: NOW,
    )
    offer = capability_offer(
        correlation_id=CORRELATION_ID,
        harness="codex",
        original_hook_attached=False,
        wait_deadline=None,
        opaque_target_id="codex-thread-opaque-01",
        session_target_verified=True,
    )

    started = monotonic()
    result = coordinator.continue_after_application(offer, action="allow_once", timeout_seconds=0.02)

    assert monotonic() - started < 0.2
    assert result.status == "failed"
    assert result.reason == "continuation_adapter_timeout"
    assert attempts == [result]
    assert adapter.cancelled.wait(0.2)


def test_failed_attempt_persistence_never_populates_the_in_memory_cache() -> None:
    adapter = FakeAdapter()
    offer = ContinuationOffer(
        correlation_id=CORRELATION_ID,
        harness="codex",
        capability="suspended-response",
        original_hook_attached=True,
        wait_deadline=NOW + timedelta(seconds=10),
    )
    coordinator = ContinuationCoordinator(
        adapter,
        record_attempt=lambda _offer, _action, _result: (_ for _ in ()).throw(RuntimeError("store unavailable")),
        notify_manual_retry=lambda _offer, _result: None,
        now=lambda: NOW,
    )

    with pytest.raises(RuntimeError, match="store unavailable"):
        coordinator.continue_after_application(offer, action="allow_once", timeout_seconds=3)
    with pytest.raises(RuntimeError, match="store unavailable"):
        coordinator.continue_after_application(offer, action="allow_once", timeout_seconds=3)

    assert adapter.calls == 2


def test_terminal_evidence_identifiers_are_unique() -> None:
    offer = capability_offer(
        correlation_id=CORRELATION_ID,
        harness="pi",
        original_hook_attached=False,
        wait_deadline=None,
    )
    results: list[ContinuationResult] = []
    for _ in range(2):
        coordinator = ContinuationCoordinator(
            FakeAdapter(),
            record_attempt=lambda _offer, _action, result: results.append(result),
            notify_manual_retry=lambda _offer, _result: None,
            now=lambda: NOW,
        )
        coordinator.continue_after_application(offer, action="allow_once", timeout_seconds=3)

    assert results[0].evidence_id != results[1].evidence_id
