"""Coalesced storage-independent daemon heartbeat persistence."""

from __future__ import annotations

import threading
from typing import Protocol, final


class RuntimeHeartbeatStore(Protocol):
    def try_touch_runtime_state(
        self,
        *,
        session_id: str,
        last_heartbeat_at: str,
        timeout_seconds: float,
    ) -> bool: ...


@final
class RuntimeHeartbeatWriter:
    """Persist only the newest heartbeat outside request-handling threads."""

    def __init__(
        self,
        *,
        store: RuntimeHeartbeatStore,
        session_id: str,
        write_timeout_seconds: float = 0.05,
        retry_interval_seconds: float = 0.05,
    ) -> None:
        self._store = store
        self._session_id = session_id
        self._write_timeout_seconds = max(write_timeout_seconds, 0.0)
        self._retry_interval_seconds = max(retry_interval_seconds, 0.001)
        self._condition = threading.Condition()
        self._pending_heartbeat: str | None = None
        self._stopping = False
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        with self._condition:
            if self._thread is not None and self._thread.is_alive():
                return
            self._stopping = False
            self._thread = threading.Thread(
                target=self._run,
                daemon=True,
                name="guard-runtime-heartbeat-writer",
            )
            self._thread.start()

    def touch(self, last_heartbeat_at: str) -> None:
        with self._condition:
            if self._stopping:
                return
            self._pending_heartbeat = last_heartbeat_at
            self._condition.notify()

    def stop(self, *, timeout_seconds: float = 1.0) -> bool:
        with self._condition:
            self._stopping = True
            self._condition.notify_all()
            thread = self._thread
        if thread is not None:
            thread.join(timeout=max(timeout_seconds, 0.0))
        with self._condition:
            if self._thread is thread and (thread is None or not thread.is_alive()):
                self._thread = None
            return self._thread is None

    def _run(self) -> None:
        while True:
            with self._condition:
                while self._pending_heartbeat is None and not self._stopping:
                    _ = self._condition.wait()
                if self._stopping:
                    return
                heartbeat = self._pending_heartbeat
            assert heartbeat is not None
            succeeded = False
            try:
                succeeded = self._store.try_touch_runtime_state(
                    session_id=self._session_id,
                    last_heartbeat_at=heartbeat,
                    timeout_seconds=self._write_timeout_seconds,
                )
            except Exception:
                succeeded = False
            with self._condition:
                if succeeded and self._pending_heartbeat == heartbeat:
                    self._pending_heartbeat = None
                if self._stopping:
                    return
                if not succeeded:
                    _ = self._condition.wait(timeout=self._retry_interval_seconds)
