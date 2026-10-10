"""Non-blocking, bounded-retry persistence for daemon security audit events.

Audit writes run on request threads that are already answering a rejection, so
they must never stall the response or flood the log. One synchronous attempt
keeps the common case immediate and ordered. If SQLite reports contention
(`database is locked`, or the short wait times out), the event is handed to a
bounded background retry queue instead of being dropped or retried inline.

Bounds:

* the synchronous attempt waits at most ``attempt_timeout_seconds``;
* at most ``capacity`` events wait for retry; extra events are counted, not kept;
* each event gets at most ``len(retry_delays) + 1`` attempts in total;
* failures are logged once per ``log_window_seconds`` with a suppressed count;
* ``close`` gives queued retries at most ``close_timeout_seconds`` to finish.

Only transient lock contention is retried. Other database errors are logged and
not retried. Losing an audit row never changes the security decision.
"""

from __future__ import annotations

import queue
import sqlite3
import threading
import time
from collections.abc import Callable
from typing import TYPE_CHECKING, Final

from ..sqlite_tuning import sqlite_connect_timeout_override

if TYPE_CHECKING:
    from ..store import GuardStore
    from .diagnostics import DaemonDiagnostics

FAILED_EVENT: Final = "auth_audit_persistence_failed"
DROPPED_EVENT: Final = "auth_audit_persistence_dropped"
_LOCK_MARKERS: Final = ("database is locked", "database table is locked")
DEFAULT_ATTEMPT_TIMEOUT_SECONDS: Final = 0.25
DEFAULT_RETRY_DELAYS: Final = (0.2, 0.5, 1.0, 2.0)
DEFAULT_CAPACITY: Final = 32
DEFAULT_LOG_WINDOW_SECONDS: Final = 60.0
DEFAULT_CLOSE_TIMEOUT_SECONDS: Final = 2.0

WRITTEN: Final = "written"
QUEUED: Final = "queued"
NOT_PERSISTED: Final = "not_persisted"


def is_lock_contention(error: BaseException) -> bool:
    if isinstance(error, TimeoutError):
        return True
    return isinstance(error, sqlite3.OperationalError) and any(marker in str(error).lower() for marker in _LOCK_MARKERS)


class AuditPersistence:
    """Persist audit events with one inline attempt and bounded background retries."""

    def __init__(
        self,
        store: GuardStore,
        diagnostics: DaemonDiagnostics,
        *,
        attempt_timeout_seconds: float = DEFAULT_ATTEMPT_TIMEOUT_SECONDS,
        retry_delays: tuple[float, ...] = DEFAULT_RETRY_DELAYS,
        capacity: int = DEFAULT_CAPACITY,
        log_window_seconds: float = DEFAULT_LOG_WINDOW_SECONDS,
        clock: Callable[[], float] = time.monotonic,
        wait: Callable[[float], object] | None = None,
    ) -> None:
        self._store = store
        self._diagnostics = diagnostics
        self._attempt_timeout = attempt_timeout_seconds
        self._retry_delays = retry_delays
        self._queue: queue.Queue[tuple[str, dict[str, object], str]] = queue.Queue(maxsize=max(1, capacity))
        self._clock = clock
        self._stop = threading.Event()
        self._wait = wait if wait is not None else self._stop.wait
        self._log_window = log_window_seconds
        self._log_lock = threading.Lock()
        self._log_started: dict[str, float] = {}
        self._log_suppressed: dict[str, int] = {}
        self._worker_lock = threading.Lock()
        self._worker: threading.Thread | None = None
        self.persisted_after_retry = 0

    def persist(self, event_name: str, payload: dict[str, object], now: str) -> str:
        """Write now if possible; queue retries on contention.

        Returns ``WRITTEN`` when the row is stored, ``QUEUED`` when it awaits a
        background retry that may still fail, and ``NOT_PERSISTED`` otherwise.
        """

        try:
            self._write(event_name, payload, now)
        except Exception as error:
            if not is_lock_contention(error):
                self._log(FAILED_EVENT)
                return NOT_PERSISTED
            return QUEUED if self._enqueue(event_name, payload, now) else NOT_PERSISTED
        return WRITTEN

    def close(self, timeout_seconds: float = DEFAULT_CLOSE_TIMEOUT_SECONDS) -> None:
        """Let queued retries finish for at most ``timeout_seconds``, then stop."""

        with self._worker_lock:
            worker = self._worker
        if worker is not None and worker is not threading.current_thread():
            worker.join(timeout=max(0.0, timeout_seconds))
        self._stop.set()

    def _write(self, event_name: str, payload: dict[str, object], now: str) -> None:
        with sqlite_connect_timeout_override(self._attempt_timeout):
            self._store.add_event(event_name, payload, now)

    def _enqueue(self, event_name: str, payload: dict[str, object], now: str) -> bool:
        try:
            self._queue.put_nowait((event_name, payload, now))
        except queue.Full:
            self._log(DROPPED_EVENT)
            return False
        self._ensure_worker()
        return True

    def _ensure_worker(self) -> None:
        with self._worker_lock:
            if self._worker is not None:
                return
            self._worker = threading.Thread(target=self._drain, daemon=True, name="guard-audit-persistence")
            self._worker.start()

    def _drain(self) -> None:
        try:
            while not self._stop.is_set():
                try:
                    event_name, payload, now = self._queue.get_nowait()
                except queue.Empty:
                    # Decide to exit under the same lock producers take in
                    # `_ensure_worker`, so an event queued after our empty check
                    # either is seen here or starts a fresh worker.
                    with self._worker_lock:
                        if self._queue.empty():
                            self._worker = None
                            return
                    continue
                self._retry_one(event_name, payload, now)
        finally:
            with self._worker_lock:
                if self._worker is threading.current_thread():
                    self._worker = None

    def _retry_one(self, event_name: str, payload: dict[str, object], now: str) -> None:
        for delay in self._retry_delays:
            self._wait(delay)
            if self._stop.is_set():
                return
            try:
                self._write(event_name, payload, now)
            except Exception as error:
                if is_lock_contention(error):
                    continue
                self._log(FAILED_EVENT)
                return
            self.persisted_after_retry += 1
            return
        self._log(FAILED_EVENT)

    def _log(self, event: str) -> None:
        """Log ``event`` once per window; later occurrences only bump a counter."""

        now = self._clock()
        with self._log_lock:
            started = self._log_started.get(event)
            if started is not None and now - started < self._log_window:
                self._log_suppressed[event] = self._log_suppressed.get(event, 0) + 1
                return
            suppressed = self._log_suppressed.pop(event, 0)
            self._log_started[event] = now
        detail = f"suppressed_since_last_log={suppressed}" if suppressed else None
        self._diagnostics.record_exception(event, detail=detail)


__all__ = ["NOT_PERSISTED", "QUEUED", "WRITTEN", "AuditPersistence", "is_lock_contention"]
