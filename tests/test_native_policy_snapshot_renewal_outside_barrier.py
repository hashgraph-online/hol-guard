"""Direct-lane ACK renewal runs without holding the publisher's barrier lock.

Renewal rewrites the ACK file. On Windows that is several resident round
trips, each up to a second on a loaded host, and hooks take the barrier lock
to register a workspace or read the current snapshot. Renewal is ordered
against invalidation by the direct lane's own lock, so the barrier lock must
be free while it runs.
"""

from __future__ import annotations

import threading
import time

import pytest

from codex_plugin_scanner.guard import native_policy_snapshot_publication as publication
from codex_plugin_scanner.guard.native_policy_snapshot_publication import NativePolicySnapshotPublicationMixin


class _Publisher:
    def __init__(self) -> None:
        self._condition = threading.Condition()
        self._closed = False
        self._acked = False
        self._poll_interval_seconds = 0.05
        self._retry_not_before_monotonic: float | None = None
        self._renewal_due_monotonic: float | None = None
        self._renewal_after_generation: int | None = None
        self._failure_count = 0
        self._snapshot = None
        self._publish_event = threading.Event()
        self._publish_event.set()
        self.expired_checks = 0
        self.barrier_free_during_renewal: list[bool] = []

    def _monotonic_clock(self) -> float:
        return time.monotonic()

    def _mark_expired_locked(self) -> None:
        self.expired_checks += 1

    def _renew_direct_lane_ack(self) -> None:
        free: list[bool] = []

        def probe() -> None:
            acquired = self._condition.acquire(timeout=0.5)
            free.append(acquired)
            if acquired:
                self._condition.release()

        thread = threading.Thread(target=probe)
        thread.start()
        thread.join()
        self.barrier_free_during_renewal.append(free[0])
        self._publish_event.set()
        if len(self.barrier_free_during_renewal) >= 2:
            self._closed = True

    def _note_publish_attempt(self) -> None:
        pass

    def _publish_once(self, *, renew_after_generation: int | None) -> None:
        pass


def test_renewal_leaves_the_barrier_lock_free(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(publication, "reconcile_policy_inputs", lambda _publisher: None)
    publisher = _Publisher()

    NativePolicySnapshotPublicationMixin._run_until_closed(publisher, publisher)  # type: ignore[arg-type]

    assert publisher.barrier_free_during_renewal == [True, True]
    # Expiry is still checked under the lock before each renewal.
    assert publisher.expired_checks >= 3
