from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor

import pytest

from codex_plugin_scanner.guard.daemon.runtime_hook_scheduler import RuntimeHookScheduler
from tests.coverage_ci import UNDER_COVERAGE_TRACING, under_coverage_scale


def test_scheduler_waits_for_capacity_instead_of_rejecting() -> None:
    scheduler = RuntimeHookScheduler(active_limit=1)
    first = scheduler.acquire(
        harness="pi",
        client_key="one",
        lane="decision",
        payload_bytes=10,
        deadline=time.monotonic() + 1,
    )
    assert first.permit is not None

    with ThreadPoolExecutor(max_workers=1) as executor:
        waiting = executor.submit(
            scheduler.acquire,
            harness="pi",
            client_key="two",
            lane="decision",
            payload_bytes=10,
            deadline=time.monotonic() + 1,
        )
        time.sleep(0.02)
        assert not waiting.done()
        first.permit.release()
        second = waiting.result(timeout=1)

    assert second.permit is not None
    second.permit.release()
    assert scheduler.stats()["completed"] == 2
    assert scheduler.stats()["rejected"] == {}


def test_scheduler_dynamic_capacity_wakes_waiter() -> None:
    scheduler = RuntimeHookScheduler(active_limit=0)

    with ThreadPoolExecutor(max_workers=1) as executor:
        waiting = executor.submit(
            scheduler.acquire,
            harness="pi",
            client_key="one",
            lane="decision",
            payload_bytes=1,
            deadline=time.monotonic() + 1,
        )
        time.sleep(0.02)
        assert not waiting.done()
        scheduler.set_active_limit(1)
        admitted = waiting.result(timeout=1)

    assert admitted.permit is not None
    admitted.permit.release()
    assert scheduler.stats()["active_limit"] == 1


@pytest.mark.skipif(
    UNDER_COVERAGE_TRACING,
    reason="Concurrent scheduler throughput shifts under coverage tracing; run untraced",
)
def test_scheduler_handles_48_routine_reviews_without_capacity_rejection() -> None:
    coverage_scale = under_coverage_scale(3.0)
    scheduler = RuntimeHookScheduler(
        active_limit=8,
        queued_limit=64,
        per_harness_queued_limit=64,
        per_client_queued_limit=16,
    )
    barrier = threading.Barrier(48)

    def review(index: int) -> None:
        barrier.wait(timeout=8 * coverage_scale)
        admission = scheduler.acquire(
            harness="pi",
            client_key=f"client-{index % 6}",
            lane="decision",
            payload_bytes=1,
            deadline=time.monotonic() + 8 * coverage_scale,
        )
        assert admission.permit is not None
        time.sleep(0.002)
        admission.permit.release()

    with ThreadPoolExecutor(max_workers=48) as executor:
        futures = [executor.submit(review, index) for index in range(48)]
        for future in futures:
            future.result(timeout=12 * coverage_scale)

    stats = scheduler.stats()
    assert stats["completed"] == 48
    assert stats["rejected"] == {}
    assert stats["queue_wait_p95_ms"] > 0
    assert stats["service_time_p95_ms"] > 0


def test_scheduler_expires_waiter_at_its_deadline() -> None:
    scheduler = RuntimeHookScheduler(active_limit=1)
    first = scheduler.acquire(
        harness="pi",
        client_key="one",
        lane="decision",
        payload_bytes=10,
        deadline=time.monotonic() + 1,
    )
    assert first.permit is not None

    expired = scheduler.acquire(
        harness="pi",
        client_key="two",
        lane="decision",
        payload_bytes=10,
        deadline=time.monotonic() + 0.01,
    )
    first.permit.release()

    assert expired.permit is None
    assert expired.reason_code == "daemon_hook_deadline_exhausted"
    assert scheduler.stats()["expired"] == 1


def test_scheduler_enforces_byte_capacity() -> None:
    scheduler = RuntimeHookScheduler(active_limit=1, retained_bytes_limit=10)
    first = scheduler.acquire(
        harness="pi",
        client_key="one",
        lane="decision",
        payload_bytes=10,
        deadline=time.monotonic() + 1,
    )
    assert first.permit is not None

    rejected = scheduler.acquire(
        harness="pi",
        client_key="two",
        lane="decision",
        payload_bytes=1,
        deadline=time.monotonic() + 1,
    )
    first.permit.release()

    assert rejected.permit is None
    assert rejected.reason_code == "daemon_hook_queue_bytes"


def test_scheduler_round_robins_clients() -> None:
    scheduler = RuntimeHookScheduler(active_limit=1)
    first = scheduler.acquire(
        harness="pi",
        client_key="first",
        lane="decision",
        payload_bytes=1,
        deadline=time.monotonic() + 1,
    )
    assert first.permit is not None
    order: list[str] = []
    lock = threading.Lock()

    def run(client: str) -> None:
        admission = scheduler.acquire(
            harness="pi",
            client_key=client,
            lane="decision",
            payload_bytes=1,
            deadline=time.monotonic() + 2,
        )
        assert admission.permit is not None
        with lock:
            order.append(client)
        admission.permit.release()

    with ThreadPoolExecutor(max_workers=3) as executor:
        futures = [
            executor.submit(run, "first"),
            executor.submit(run, "second"),
            executor.submit(run, "first"),
        ]
        time.sleep(0.02)
        first.permit.release()
        for future in futures:
            future.result(timeout=1)

    assert order[0] == "first"
    assert order[1] == "second"


def test_scheduler_bounds_pending_items_per_client() -> None:
    scheduler = RuntimeHookScheduler(active_limit=1, per_client_queued_limit=1)
    active = scheduler.acquire(
        harness="pi",
        client_key="active",
        lane="decision",
        payload_bytes=1,
        deadline=time.monotonic() + 1,
    )
    assert active.permit is not None

    with ThreadPoolExecutor(max_workers=1) as executor:
        waiting = executor.submit(
            scheduler.acquire,
            harness="pi",
            client_key="queued",
            lane="decision",
            payload_bytes=1,
            deadline=time.monotonic() + 1,
        )
        time.sleep(0.02)
        rejected = scheduler.acquire(
            harness="pi",
            client_key="queued",
            lane="decision",
            payload_bytes=1,
            deadline=time.monotonic() + 1,
        )
        active.permit.release()
        admitted = waiting.result(timeout=1)

    assert rejected.reason_code == "daemon_hook_queue_capacity"
    assert admitted.permit is not None
    admitted.permit.release()


def test_scheduler_reserves_active_capacity_for_another_harness() -> None:
    scheduler = RuntimeHookScheduler(active_limit=2, per_harness_active_limit=1)
    first_pi = scheduler.acquire(
        harness="pi",
        client_key="pi-one",
        lane="decision",
        payload_bytes=1,
        deadline=time.monotonic() + 1,
    )
    assert first_pi.permit is not None

    with ThreadPoolExecutor(max_workers=1) as executor:
        waiting_pi = executor.submit(
            scheduler.acquire,
            harness="pi",
            client_key="pi-two",
            lane="decision",
            payload_bytes=1,
            deadline=time.monotonic() + 1,
        )
        time.sleep(0.02)
        claude = scheduler.acquire(
            harness="claude-code",
            client_key="claude",
            lane="decision",
            payload_bytes=1,
            deadline=time.monotonic() + 1,
        )
        assert claude.permit is not None
        assert not waiting_pi.done()
        first_pi.permit.release()
        second_pi = waiting_pi.result(timeout=1)

    assert second_pi.permit is not None
    second_pi.permit.release()
    claude.permit.release()


def test_scheduler_does_not_block_uncapped_harness_for_same_client() -> None:
    scheduler = RuntimeHookScheduler(active_limit=2, per_harness_active_limit=1)
    first_pi = scheduler.acquire(
        harness="pi",
        client_key="shared-workspace",
        lane="decision",
        payload_bytes=1,
        deadline=time.monotonic() + 1,
    )
    assert first_pi.permit is not None

    with ThreadPoolExecutor(max_workers=2) as executor:
        waiting_pi = executor.submit(
            scheduler.acquire,
            harness="pi",
            client_key="shared-workspace",
            lane="decision",
            payload_bytes=1,
            deadline=time.monotonic() + 1,
        )
        time.sleep(0.02)
        waiting_claude = executor.submit(
            scheduler.acquire,
            harness="claude-code",
            client_key="shared-workspace",
            lane="decision",
            payload_bytes=1,
            deadline=time.monotonic() + 1,
        )
        claude = waiting_claude.result(timeout=1)
        assert claude.permit is not None
        assert not waiting_pi.done()
        first_pi.permit.release()
        second_pi = waiting_pi.result(timeout=1)

    assert second_pi.permit is not None
    second_pi.permit.release()
    claude.permit.release()


def test_scheduler_bounds_bytes_before_payload_hydration() -> None:
    scheduler = RuntimeHookScheduler(retained_bytes_limit=10)
    reservation, reason = scheduler.reserve_bytes(
        payload_bytes=10,
        deadline=time.monotonic() + 1,
    )
    assert reservation is not None
    assert reason is None

    with ThreadPoolExecutor(max_workers=1) as executor:
        waiting = executor.submit(
            scheduler.reserve_bytes,
            payload_bytes=1,
            deadline=time.monotonic() + 1,
        )
        time.sleep(0.02)
        assert not waiting.done()
        reservation.release()
        admitted, admitted_reason = waiting.result(timeout=1)

    assert admitted is not None
    assert admitted_reason is None
    admitted.release()
    assert scheduler.stats()["retained_bytes"] == 0


def test_expired_waiter_wakes_byte_reservation_when_dispatch_remains_blocked() -> None:
    scheduler = RuntimeHookScheduler(
        active_limit=2,
        per_harness_active_limit=1,
        retained_bytes_limit=3,
    )
    active = scheduler.acquire(
        harness="pi",
        client_key="active",
        lane="decision",
        payload_bytes=1,
        deadline=time.monotonic() + 1,
    )
    assert active.permit is not None

    with ThreadPoolExecutor(max_workers=3) as executor:
        expires_at = time.monotonic() + 0.5
        expired = executor.submit(
            scheduler.acquire,
            harness="pi",
            client_key="expired",
            lane="decision",
            payload_bytes=1,
            deadline=expires_at,
        )
        waiting = executor.submit(
            scheduler.acquire,
            harness="pi",
            client_key="waiting",
            lane="decision",
            payload_bytes=1,
            deadline=time.monotonic() + 2,
        )
        readiness_deadline = time.monotonic() + 0.25
        while scheduler.stats()["queued"] < 2 and time.monotonic() < readiness_deadline:
            time.sleep(0.001)
        assert scheduler.stats()["queued"] == 2
        reservation = executor.submit(
            scheduler.reserve_bytes,
            payload_bytes=1,
            deadline=expires_at + 1,
        )

        assert expired.result(timeout=1).reason_code == "daemon_hook_deadline_exhausted"
        admitted, reason = reservation.result(timeout=0.25)
        assert admitted is not None
        assert reason is None
        admitted.release()
        active.permit.release()
        queued = waiting.result(timeout=0.25)

    assert queued.permit is not None
    queued.permit.release()


def test_scheduler_rejects_single_payload_larger_than_byte_limit() -> None:
    scheduler = RuntimeHookScheduler(retained_bytes_limit=10)

    reservation, reason = scheduler.reserve_bytes(
        payload_bytes=11,
        deadline=time.monotonic() + 1,
    )

    assert reservation is None
    assert reason == "daemon_hook_queue_bytes"


def test_scheduler_atomically_grows_and_shrinks_payload_reservation() -> None:
    scheduler = RuntimeHookScheduler(retained_bytes_limit=10)
    reservation, reason = scheduler.reserve_bytes(
        payload_bytes=5,
        deadline=time.monotonic() + 1,
    )
    assert reservation is not None
    assert reason is None

    assert reservation.resize(10, deadline=time.monotonic() + 1) is None
    assert scheduler.stats()["retained_bytes"] == 10
    assert reservation.resize(3, deadline=time.monotonic() + 1) is None
    assert scheduler.stats()["retained_bytes"] == 3
    reservation.release()

    assert scheduler.stats()["retained_bytes"] == 0


def test_scheduler_rejects_reservation_growth_beyond_global_limit() -> None:
    scheduler = RuntimeHookScheduler(retained_bytes_limit=10)
    reservation, reason = scheduler.reserve_bytes(
        payload_bytes=5,
        deadline=time.monotonic() + 1,
    )
    assert reservation is not None
    assert reason is None

    assert reservation.resize(11, deadline=time.monotonic() + 1) == "daemon_hook_queue_bytes"
    reservation.release()
    assert scheduler.stats()["retained_bytes"] == 0


@pytest.mark.parametrize("previous_owner", ["released", "transferred"])
def test_invalid_byte_reservation_cannot_publish_phantom_queued_work(previous_owner: str) -> None:
    scheduler = RuntimeHookScheduler(active_limit=1, retained_bytes_limit=10)
    reservation, reason = scheduler.reserve_bytes(payload_bytes=5, deadline=time.monotonic() + 1)
    assert reservation is not None and reason is None
    if previous_owner == "released":
        reservation.release()
    else:
        previous = scheduler.acquire(
            harness="codex",
            client_key="previous",
            lane="decision",
            payload_bytes=5,
            deadline=time.monotonic() + 1,
            byte_reservation=reservation,
        )
        assert previous.permit is not None
        previous.permit.release()
    baseline = scheduler.stats()
    assert baseline["active"] == baseline["queued"] == baseline["retained_bytes"] == 0
    with pytest.raises(RuntimeError, match="no longer transferable"):
        scheduler.acquire(
            harness="codex",
            client_key="invalid",
            lane="decision",
            payload_bytes=5,
            deadline=time.monotonic() + 1,
            byte_reservation=reservation,
        )
    assert scheduler.stats() == baseline, "rejected ownership must not enqueue or change byte accounting"
    next_request = scheduler.acquire(
        harness="pi",
        client_key="next",
        lane="decision",
        payload_bytes=10,
        deadline=time.monotonic() + 1,
    )
    assert next_request.permit is not None
    next_request.permit.release()
    final = scheduler.stats()
    assert final["active"] == final["queued"] == final["retained_bytes"] == 0


def test_cancelling_queued_reserved_payload_returns_bytes_without_releasing_active_owner() -> None:
    scheduler = RuntimeHookScheduler(active_limit=1, retained_bytes_limit=10)
    active = scheduler.acquire(
        harness="pi",
        client_key="active",
        lane="decision",
        payload_bytes=5,
        deadline=time.monotonic() + 2,
    )
    assert active.permit is not None
    reservation, reason = scheduler.reserve_bytes(payload_bytes=5, deadline=time.monotonic() + 1)
    assert reservation is not None and reason is None
    cancellation = threading.Event()
    with ThreadPoolExecutor(max_workers=1) as executor:
        queued = executor.submit(
            scheduler.acquire,
            harness="codex",
            client_key="cancelled",
            lane="decision",
            payload_bytes=5,
            deadline=time.monotonic() + 2,
            byte_reservation=reservation,
            cancellation=cancellation,
        )
        try:
            until = time.monotonic() + 1
            while scheduler.stats()["queued"] != 1 and time.monotonic() < until:
                time.sleep(0.001)
            assert scheduler.stats()["queued"] == 1
            assert scheduler.stats()["retained_bytes"] == 10
            cancellation.set()
            result = queued.result(timeout=1)
            assert result.permit is None and result.reason_code == "daemon_hook_deadline_exhausted"
            reservation.release()  # Ownership transferred; caller cleanup cannot double-release.
            stats = scheduler.stats()
            assert stats["active"] == 1 and stats["queued"] == 0
            assert stats["retained_bytes"] == 5 and stats["cancelled"] == 1
            assert stats["per_harness_active"] == {"pi": 1}
            assert not stats["per_harness_queued"]
        finally:
            cancellation.set()
            active.permit.release()
    final = scheduler.stats()
    assert final["active"] == final["queued"] == final["retained_bytes"] == 0
    print(
        "C2 pass repetitions=1 active=0 queued=0 retained_bytes=0 "
        f"cancelled={final['cancelled']} baseline_retained_bytes=0"
    )


def test_default_scheduler_admits_thirty_two_hooks_across_harnesses() -> None:
    """The production scheduler bounds are 32 active hooks and 24 for one harness."""

    scheduler = RuntimeHookScheduler()
    permits = []
    for index in range(32):
        harness = "codex" if index < 24 else "pi"
        result = scheduler.acquire(
            harness=harness,
            client_key=f"hook-{index}",
            lane="decision",
            payload_bytes=1,
            deadline=time.monotonic() + 1,
        )
        assert result.permit is not None, result.reason_code
        permits.append(result.permit)
    stats = scheduler.stats()
    assert stats["active"] == 32
    assert stats["per_harness_active"] == {"codex": 24, "pi": 8}
    for permit in permits:
        permit.release()
    final = scheduler.stats()
    assert final["active"] == final["queued"] == final["retained_bytes"] == 0
    print(f"C1 pass hooks=32 codex=24 pi=8 active_limit=32 retained_bytes_after={final['retained_bytes']}")


def test_repeated_cancellation_returns_hook_scheduler_baseline() -> None:
    """Cancelled admissions release permits and reserved bytes back to the baseline."""

    before_threads = threading.active_count()
    scheduler = RuntimeHookScheduler(active_limit=0, retained_bytes_limit=64)
    for index in range(8):
        reservation, reason = scheduler.reserve_bytes(payload_bytes=8, deadline=time.monotonic() + 1)
        assert reservation is not None and reason is None
        cancellation = threading.Event()
        cancellation.set()
        result = scheduler.acquire(
            harness="codex" if index % 2 == 0 else "pi",
            client_key=f"client-{index}",
            lane="decision",
            payload_bytes=8,
            deadline=time.monotonic() + 1,
            byte_reservation=reservation,
            cancellation=cancellation,
        )
        assert result.permit is None
        assert result.reason_code == "daemon_hook_deadline_exhausted"
        reservation.release()
    stats = scheduler.stats()
    assert stats["active"] == stats["queued"] == stats["retained_bytes"] == 0
    assert stats["cancelled"] == 8
    after_threads = threading.active_count()
    assert after_threads <= before_threads + 1
    print(
        "C2 pass repetitions=8 active=0 queued=0 retained_bytes=0 cancelled=8 "
        f"threads_before={before_threads} threads_after={after_threads}"
    )


@pytest.mark.parametrize("reserved", [False, True])
@pytest.mark.parametrize("callback_admits", [False, True])
def test_queue_notification_exception_cannot_leave_unowned_payload(reserved: bool, callback_admits: bool) -> None:
    failure = RuntimeError("generated queue notification failure")

    def failed_notification() -> None:
        if callback_admits:
            scheduler.set_active_limit(1)
        raise failure

    scheduler = RuntimeHookScheduler(active_limit=0, retained_bytes_limit=10, queue_listener=failed_notification)
    reservation = None
    if reserved:
        reservation, reason = scheduler.reserve_bytes(payload_bytes=10, deadline=time.monotonic() + 1)
        assert reservation is not None and reason is None
    try:
        with pytest.raises(RuntimeError) as raised:
            scheduler.acquire(
                harness="codex",
                client_key="failed-notification",
                lane="decision",
                payload_bytes=10,
                deadline=time.monotonic() + 1,
                byte_reservation=reservation,
            )
        assert raised.value is failure
    finally:
        if reservation is not None:
            reservation.release()
    stats = scheduler.stats()
    assert stats["active"] == stats["queued"] == stats["retained_bytes"] == 0
    assert not stats["per_harness_queued"]
    scheduler.set_active_limit(1)
    following = scheduler.acquire(
        harness="pi",
        client_key="following",
        lane="decision",
        payload_bytes=10,
        deadline=time.monotonic() + 1,
    )
    assert following.permit is not None
    following.permit.release()
    final = scheduler.stats()
    assert final["active"] == final["queued"] == final["retained_bytes"] == 0


@pytest.mark.parametrize("admitted_before_interrupt", [False, True])
def test_interrupted_scheduler_wait_returns_ownership_before_propagating(
    monkeypatch: pytest.MonkeyPatch,
    admitted_before_interrupt: bool,
) -> None:
    scheduler = RuntimeHookScheduler(active_limit=0, retained_bytes_limit=10)
    interruption = KeyboardInterrupt("generated isolated waiter interruption")

    def interrupted_wait(timeout: float | None = None) -> bool:
        del timeout
        if admitted_before_interrupt:
            scheduler.set_active_limit(1)
        raise interruption

    with monkeypatch.context() as waiter_patch:
        waiter_patch.setattr(scheduler._condition, "wait", interrupted_wait)
        with pytest.raises(KeyboardInterrupt) as raised:
            scheduler.acquire(
                harness="codex",
                client_key="interrupted",
                lane="decision",
                payload_bytes=10,
                deadline=time.monotonic() + 1,
            )
        assert raised.value is interruption
    stats = scheduler.stats()
    assert stats["active"] == stats["queued"] == stats["retained_bytes"] == 0
    assert not stats["per_harness_active"] and not stats["per_harness_queued"]
    scheduler.set_active_limit(1)
    following = scheduler.acquire(
        harness="pi",
        client_key="following",
        lane="decision",
        payload_bytes=10,
        deadline=time.monotonic() + 1,
    )
    assert following.permit is not None
    following.permit.release()
    final = scheduler.stats()
    assert final["active"] == final["queued"] == final["retained_bytes"] == 0
