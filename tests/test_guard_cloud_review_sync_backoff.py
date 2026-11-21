"""Cloud Review sync worker backoff while the delivery queue is stalled."""

from __future__ import annotations

import threading
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime import cloud_review_sync as cloud_review_sync_module
from codex_plugin_scanner.guard.runtime import cloud_review_sync_worker
from tests.support.cloud_review_sync_store import Store


class TestStalledQueueBackoff:
    def test_stalled_wait_honors_server_hint_grows_and_is_capped(self) -> None:
        wait = cloud_review_sync_worker._stalled_wait
        assert wait(1, None) == cloud_review_sync_worker.STALLED_BACKOFF_BASE_SECONDS
        assert wait(2, None) == 2 * wait(1, None)
        assert wait(1, 60_000) == 60.0
        assert wait(40, None) == cloud_review_sync_worker.STALLED_BACKOFF_MAX_SECONDS
        assert wait(1, 86_400_000) == cloud_review_sync_worker.STALLED_BACKOFF_MAX_SECONDS

    def test_stalled_run_waits_instead_of_sending_the_next_due_batch(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        store = Store(tmp_path)
        uploads: list[int] = []
        waits: list[float] = []

        class Stop:
            def is_set(self) -> bool:
                # Bounded so a worker that ignores the stall cannot spin forever.
                return len(waits) >= 2 or len(uploads) >= 5

        class Wake:
            def generation(self) -> int:
                return 0

            def wait(self, generation: int, timeout: float) -> int:
                del generation
                waits.append(timeout)
                return 0

        monkeypatch.setattr(cloud_review_sync_module, "_resolve_cloud_review_sync_auth_context", lambda _store: {})
        monkeypatch.setattr(
            cloud_review_sync_module,
            "sync_cloud_review_events_once",
            lambda _store, _auth: (
                uploads.append(1)
                or {"synced": 0, "stalled": True, "retry_after_ms": 20_000, "outbox": {"ready_depth": 31}}
            ),
        )
        cloud_review_sync_worker._cloud_sync_sync_loop(store, Stop(), Wake(), poll_interval=1, error_backoff=1)

        assert len(uploads) == 2
        assert waits == [20.0, 20.0]


class TestStalledQueueBackoffEdges:
    @staticmethod
    def _loop(store: Store, monkeypatch: pytest.MonkeyPatch, stop: object, wake: object, results: list[object]) -> None:
        pending = iter(results)

        def sync_once(_store: object, _auth: object) -> dict[str, object]:
            outcome = next(pending)
            if isinstance(outcome, BaseException):
                raise outcome
            return outcome  # type: ignore[return-value]

        monkeypatch.setattr(cloud_review_sync_module, "_resolve_cloud_review_sync_auth_context", lambda _store: {})
        monkeypatch.setattr(cloud_review_sync_module, "sync_cloud_review_events_once", sync_once)
        cloud_review_sync_worker._cloud_sync_sync_loop(store, stop, wake, poll_interval=1, error_backoff=1)  # type: ignore[arg-type]

    def test_a_failed_sync_ends_the_stalled_streak(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        store = Store(tmp_path)
        waits: list[float] = []
        stalled = {"synced": 0, "stalled": True, "outbox": {"ready_depth": 3}}

        class Stop:
            def is_set(self) -> bool:
                return len(waits) >= 3

        class Wake:
            def generation(self) -> int:
                return 0

            def wait(self, generation: int, timeout: float) -> int:
                del generation
                waits.append(timeout)
                return 0

        self._loop(store, monkeypatch, Stop(), Wake(), [stalled, RuntimeError("boom"), stalled])

        base = cloud_review_sync_worker.STALLED_BACKOFF_BASE_SECONDS
        assert waits[0] == base
        assert waits[2] == base

    def test_stop_requested_during_a_stalled_run_is_not_slept_through(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        store = Store(tmp_path)
        waits: list[float] = []
        stop = threading.Event()

        class Wake:
            def generation(self) -> int:
                return 0

            def wait(self, generation: int, timeout: float) -> int:
                del generation
                waits.append(timeout)
                return 0

        def stalled_then_stop() -> dict[str, object]:
            stop.set()
            return {"synced": 0, "stalled": True, "outbox": {"ready_depth": 3}}

        pending = iter([stalled_then_stop])
        monkeypatch.setattr(cloud_review_sync_module, "_resolve_cloud_review_sync_auth_context", lambda _store: {})
        monkeypatch.setattr(
            cloud_review_sync_module, "sync_cloud_review_events_once", lambda _store, _auth: next(pending)()
        )
        cloud_review_sync_worker._cloud_sync_sync_loop(store, stop, Wake(), poll_interval=1, error_backoff=1)

        assert waits == []
