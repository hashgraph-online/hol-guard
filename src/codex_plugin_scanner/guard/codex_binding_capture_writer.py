"""Bounded daemon queue for optional sealed capture persistence."""

from __future__ import annotations

import json
import threading
from collections import deque
from collections.abc import Mapping
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path

from .codex_binding_capture import record_native_worker
from .codex_binding_capture_bounds import canonical_json_bytes

_QUEUE_LIMIT = 8


@dataclass(frozen=True, slots=True)
class _CaptureTask:
    guard_home: Path
    payload: bytes
    receipt: bytes


class CodexBindingCaptureWriter:
    """Keep capture file I/O out of native review and response delivery.

    Submission snapshots bounded JSON after the authority fence, never waits
    for the queue lock, and drops diagnostics when busy or full. The daemon
    owns the worker; shutdown does not wait for capture file I/O to finish.
    """

    def __init__(self) -> None:
        self._pending: deque[_CaptureTask] = deque()
        self._lock = threading.Lock()
        self._stopped = threading.Event()
        self._thread = threading.Thread(target=self._run, name="codex-binding-capture", daemon=True)
        self._thread.start()

    def submit_native_capture(
        self,
        *,
        guard_home: Path,
        payload: Mapping[str, object],
        receipt: Mapping[str, object],
    ) -> bool:
        if self._stopped.is_set() or receipt.get("harness") != "codex":
            return False
        if not self._lock.acquire(blocking=False):
            return False
        try:
            if self._stopped.is_set() or len(self._pending) >= _QUEUE_LIMIT:
                return False
            payload_bytes = canonical_json_bytes(payload)
            receipt_bytes = canonical_json_bytes(receipt)
            if payload_bytes is None or receipt_bytes is None:
                return False
            self._pending.append(_CaptureTask(guard_home, payload_bytes, receipt_bytes))
            return True
        finally:
            self._lock.release()

    def stop_capture(self) -> None:
        # Never wait for an in-flight write. The event prevents queued work
        # from running even if a submission temporarily owns the queue lock.
        self._stopped.set()
        if self._lock.acquire(blocking=False):
            try:
                self._pending.clear()
            finally:
                self._lock.release()

    def _run(self) -> None:
        while not self._stopped.wait(0.01):
            with self._lock:
                task = self._pending.popleft() if self._pending else None
            if task is None or self._stopped.is_set():
                continue
            with suppress(OSError, json.JSONDecodeError):
                receipt = json.loads(task.receipt)
                _ = record_native_worker(
                    guard_home=task.guard_home,
                    payload=json.loads(task.payload),
                    harness="codex",
                    event_name=receipt["event_name"],
                    receipt=receipt,
                )


def start_codex_binding_capture_writer() -> CodexBindingCaptureWriter | None:
    try:
        return CodexBindingCaptureWriter()
    except Exception:
        return None
