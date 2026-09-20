"""Observe the owned smoke publisher without changing its startup or retries.

Only fixed error labels and nonblocking publisher-state reads are retained.
There is no process inspection, file read, request, wait, or native override in
these callbacks. The ordinary failure exporter writes this bounded history
only when the original probe fails; it is not a latency qualification.
"""

from __future__ import annotations

import threading
import time
from contextlib import ExitStack
from pathlib import Path
from types import TracebackType
from typing import Any
from unittest.mock import patch

from ci.native_runtime.default_auto_failure import _code, _observe, _publisher_state
from codex_plugin_scanner.guard import native_policy_test_support
from codex_plugin_scanner.guard.native_policy_snapshot_publisher import NativePolicySnapshotPublisher

MAX_EVENTS = 16


def _event_code(value: object) -> str | None:
    if type(value) is str:
        return _code(value.strip().lower()) if len(value) <= 128 else "other"
    return _code(value)


class SmokePublicationObservation:
    """Forward the real helper factory and callbacks for one owned Guard home."""

    def __init__(self, guard_home: Path) -> None:
        self._home = guard_home
        self._owner = threading.get_ident()
        self._started = time.monotonic()
        self._stack = ExitStack()
        self._lock = threading.Lock()
        self._publisher: NativePolicySnapshotPublisher | None = None
        self._events: list[dict[str, object]] = []
        self._dropped = 0
        self._incomplete = False
        self._closed = False

    def _event(self, kind: str, code: object = None) -> None:
        if not self._lock.acquire(blocking=False):
            self._incomplete = True
            return
        try:
            if self._closed:
                self._incomplete = True
                return
            if len(self._events) == MAX_EVENTS:
                self._dropped += 1
                return
            elapsed_ms = (time.monotonic() - self._started) * 1000
            if not 0 <= elapsed_ms <= 60_000:
                elapsed_ms = None
                self._incomplete = True
            self._events.append(
                {
                    "kind": kind,
                    "code": _event_code(code),
                    "elapsed_ms": elapsed_ms,
                    "publisher": _publisher_state(self._publisher),
                }
            )
        finally:
            self._lock.release()

    def _safe_event(self, kind: str, code: object = None) -> None:
        try:
            self._event(kind, code)
        except Exception:
            self._incomplete = True

    def _attach(self, publisher: object) -> None:
        if (
            self._closed
            or threading.get_ident() != self._owner
            or type(publisher) is not NativePolicySnapshotPublisher
            or publisher.guard_home != self._home
        ):
            return
        if self._publisher is not None:
            if self._publisher is not publisher:
                self._incomplete = True
            return
        self._publisher = publisher
        original_error = publisher._record_error
        original_close = publisher.close

        def record_error(error: str) -> None:
            original_error(error)
            self._safe_event("publisher_error_recorded", error)

        def close(*args: Any, **kwargs: Any) -> None:
            self._safe_event("before_publisher_close")
            original_close(*args, **kwargs)
            self._safe_event("publisher_closed")

        self._stack.enter_context(patch.object(publisher, "_record_error", record_error))
        self._stack.enter_context(patch.object(publisher, "close", close))

    def __enter__(self) -> SmokePublicationObservation:
        original = native_policy_test_support.get_native_policy_snapshot_publisher

        def factory(*args: Any, **kwargs: Any) -> Any:
            publisher = original(*args, **kwargs)
            try:
                self._attach(publisher)
            except Exception:
                self._incomplete = True
            return publisher

        try:
            self._stack.enter_context(
                patch.object(native_policy_test_support, "get_native_policy_snapshot_publisher", factory)
            )
        except Exception:
            self._incomplete = True
        return self

    def __exit__(
        self, kind: type[BaseException] | None, error: BaseException | None, trace: TracebackType | None
    ) -> None:
        del kind, error, trace
        restored = False
        try:
            self._stack.close()
            restored = True
        except Exception:
            self._incomplete = True
        self._closed = True
        try:
            thread = self._publisher._thread if self._publisher is not None else None
            thread_alive = thread.is_alive() if thread is not None else False
            _observe(
                "smoke_publication",
                {
                    "scope": "owned_smoke_publisher_callbacks",
                    "publisher_bound": self._publisher is not None,
                    "events": list(self._events),
                    "event_bound": MAX_EVENTS,
                    "dropped_events": self._dropped,
                    "detail_incomplete": self._incomplete or self._dropped > 0 or thread_alive,
                    "publisher_thread_alive_at_restore": thread_alive,
                    "callbacks_restored": restored,
                    "latency_qualification": False,
                    "deadlines_changed": False,
                    "retries_added": False,
                },
            )
        except Exception:
            # Optional observation cannot replace the original probe result.
            pass
