from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor

from codex_plugin_scanner.guard.daemon.runtime_hook_scheduler import RuntimeHookScheduler
from tests.coverage_ci import under_coverage_scale


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
        barrier.wait(timeout=2 * coverage_scale)
        admission = scheduler.acquire(
            harness="pi",
            client_key=f"client-{index % 6}",
            lane="decision",
            payload_bytes=1,
            deadline=time.monotonic() + 2 * coverage_scale,
        )
        assert admission.permit is not None
        time.sleep(0.002)
        admission.permit.release()

    with ThreadPoolExecutor(max_workers=48) as executor:
        futures = [executor.submit(review, index) for index in range(48)]
        for future in futures:
            future.result(timeout=3 * coverage_scale)

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
