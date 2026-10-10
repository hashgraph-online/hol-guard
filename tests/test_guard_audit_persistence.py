"""Bounded, non-blocking audit persistence under SQLite lock contention."""

from __future__ import annotations

import sqlite3
import threading
import time
from pathlib import Path

from codex_plugin_scanner.guard.daemon.audit_persistence import (
    FAILED_EVENT,
    NOT_PERSISTED,
    QUEUED,
    WRITTEN,
    AuditPersistence,
)
from codex_plugin_scanner.guard.store import GuardStore


class _Diagnostics:
    def __init__(self) -> None:
        self.events: list[tuple[str, str | None]] = []

    def record_exception(self, event: str, *, detail: str | None = None, **_kwargs: object) -> bool:
        self.events.append((event, detail))
        return True


class _FlakyStore:
    def __init__(self, failures: int, error: Exception | None = None) -> None:
        self.failures = failures
        self.error = error or sqlite3.OperationalError("database is locked")
        self.calls = 0
        self.rows: list[str] = []
        self.written = threading.Event()

    def add_event(self, event_name: str, payload: dict[str, object], now: str) -> None:
        del payload, now
        self.calls += 1
        if self.calls <= self.failures:
            raise self.error
        self.rows.append(event_name)
        self.written.set()


def _persistence(store: object, diagnostics: _Diagnostics, **kwargs: object) -> AuditPersistence:
    return AuditPersistence(
        store,  # type: ignore[arg-type]
        diagnostics,  # type: ignore[arg-type]
        retry_delays=(0.0, 0.0, 0.0),
        wait=lambda _seconds: None,
        **kwargs,  # type: ignore[arg-type]
    )


def test_success_writes_inline_without_logging(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    diagnostics = _Diagnostics()
    # A loaded CI host can take longer than the 0.25s default for a first write.
    persistence = _persistence(store, diagnostics, attempt_timeout_seconds=5.0)

    assert persistence.persist("daemon.auth.unauthorized", {"path": "/x"}, "2026-01-01T00:00:00+00:00") == WRITTEN

    assert len(store.list_events(event_name="daemon.auth.unauthorized")) == 1
    assert diagnostics.events == []


def test_lock_contention_returns_immediately_and_persists_on_retry() -> None:
    store = _FlakyStore(failures=2)
    diagnostics = _Diagnostics()
    persistence = _persistence(store, diagnostics)

    started = time.monotonic()
    assert persistence.persist("daemon.auth.unauthorized", {}, "now") == QUEUED
    assert time.monotonic() - started < 1.0

    assert store.written.wait(timeout=5)
    assert store.rows == ["daemon.auth.unauthorized"]
    assert store.calls == 3
    assert diagnostics.events == []


def test_retries_are_bounded_and_failure_logged_once_per_window() -> None:
    store = _FlakyStore(failures=10_000)
    diagnostics = _Diagnostics()
    now = [0.0]
    persistence = _persistence(store, diagnostics, clock=lambda: now[0], log_window_seconds=60.0)

    for _ in range(3):
        persistence.persist("daemon.auth.unauthorized", {}, "now")
    worker = persistence._worker  # pyright: ignore[reportPrivateUsage]
    assert worker is not None
    worker.join(timeout=5)

    # 3 events * (1 inline + 3 retries) attempts, never more.
    assert store.calls == 12
    assert [event for event, _ in diagnostics.events] == [FAILED_EVENT]

    now[0] = 61.0
    persistence.persist("daemon.auth.unauthorized", {}, "now")
    persistence._worker.join(timeout=5)  # type: ignore[union-attr]  # pyright: ignore[reportPrivateUsage]
    assert [event for event, _ in diagnostics.events] == [FAILED_EVENT, FAILED_EVENT]
    assert diagnostics.events[1][1] == "suppressed_since_last_log=2"


def test_full_queue_drops_instead_of_blocking() -> None:
    store = _FlakyStore(failures=10_000)
    diagnostics = _Diagnostics()
    release = threading.Event()
    persistence = AuditPersistence(
        store,  # type: ignore[arg-type]
        diagnostics,  # type: ignore[arg-type]
        retry_delays=(0.0,),
        capacity=1,
        wait=lambda _seconds: release.wait(timeout=5),
    )

    results = [persistence.persist("e", {}, "now") for _ in range(4)]
    release.set()

    assert results.count(NOT_PERSISTED) >= 1
    assert any(event == "auth_audit_persistence_dropped" for event, _ in diagnostics.events)


def test_non_contention_error_is_not_retried() -> None:
    store = _FlakyStore(failures=10, error=sqlite3.DatabaseError("disk image is malformed"))
    diagnostics = _Diagnostics()
    persistence = _persistence(store, diagnostics)

    assert persistence.persist("e", {}, "now") == NOT_PERSISTED

    assert store.calls == 1
    assert [event for event, _ in diagnostics.events] == [FAILED_EVENT]


def test_worker_rechecks_queue_before_exiting() -> None:
    import queue as queue_module

    class _LateArrivalQueue(queue_module.Queue[tuple[str, dict[str, object], str]]):
        """Reports empty once while an event is already queued, like a racing producer."""

        def __init__(self) -> None:
            super().__init__(maxsize=4)
            self.raced = False

        def get_nowait(self) -> tuple[str, dict[str, object], str]:
            if not self.raced and self.qsize() == 1:
                self.raced = True
                raise queue_module.Empty
            return super().get_nowait()

    store = _FlakyStore(failures=1)
    persistence = _persistence(store, _Diagnostics())
    late_queue = _LateArrivalQueue()
    persistence._queue = late_queue

    assert persistence.persist("daemon.auth.unauthorized", {}, "now") == QUEUED

    assert store.written.wait(timeout=5)
    assert late_queue.raced
    assert store.rows == ["daemon.auth.unauthorized"]


def test_new_worker_starts_after_previous_one_exits() -> None:
    store = _FlakyStore(failures=1)
    persistence = _persistence(store, _Diagnostics())

    assert persistence.persist("first", {}, "now") == QUEUED
    assert store.written.wait(timeout=5)
    deadline = time.monotonic() + 5
    while persistence._worker is not None and time.monotonic() < deadline:
        time.sleep(0.01)
    assert persistence._worker is None

    store.failures = store.calls + 1
    store.written.clear()
    assert persistence.persist("second", {}, "now") == QUEUED
    assert store.written.wait(timeout=5)
    assert store.rows == ["first", "second"]


def test_close_waits_for_queued_retry_within_bound() -> None:
    store = _FlakyStore(failures=1)
    release = threading.Event()
    persistence = AuditPersistence(
        store,  # type: ignore[arg-type]
        _Diagnostics(),  # type: ignore[arg-type]
        retry_delays=(0.0,),
        wait=lambda _seconds: release.wait(timeout=0.2),
    )

    assert persistence.persist("e", {}, "now") == QUEUED
    persistence.close(timeout_seconds=5.0)

    assert store.rows == ["e"]


def test_close_is_bounded_when_retry_is_stuck() -> None:
    store = _FlakyStore(failures=1)
    release = threading.Event()
    persistence = AuditPersistence(
        store,  # type: ignore[arg-type]
        _Diagnostics(),  # type: ignore[arg-type]
        retry_delays=(0.0,),
        wait=lambda _seconds: release.wait(timeout=10),
    )

    assert persistence.persist("e", {}, "now") == QUEUED
    started = time.monotonic()
    persistence.close(timeout_seconds=0.1)
    assert time.monotonic() - started < 2.0
    release.set()
