"""Thread-scoped cancellation for native helper processes.

A long-lived owner, such as the policy snapshot publisher thread, runs many
native helper processes per pass. On Windows each one costs a binary hash and
a process start, so a pass can take seconds. Binding the owner's close event
here lets its shutdown stop the helper in flight and refuse new ones instead
of waiting out the pass. A refused helper answers like a failed one, so
callers keep their existing fail-closed handling.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from queue import Empty, Queue
from typing import TypeVar

_T = TypeVar("_T")
_STOP_POLL_SECONDS = 0.05

_STOP_EVENT: ContextVar[threading.Event | None] = ContextVar("guard_native_process_stop_event", default=None)


@contextmanager
def native_process_stop_scope(event: threading.Event) -> Iterator[None]:
    """Cancel native helper processes started in this context once ``event`` is set."""

    token = _STOP_EVENT.set(event)
    try:
        yield
    finally:
        _STOP_EVENT.reset(token)


def scoped_native_stop_event() -> threading.Event | None:
    return _STOP_EVENT.get()


def native_process_stop_requested() -> bool:
    event = _STOP_EVENT.get()
    return event is not None and event.is_set()


def get_unless_stopped(queue: Queue[_T], timeout: float) -> _T:
    """Wait for a queue item, raising ``Empty`` early once the scoped stop event is set.

    A resident-stream response wait otherwise outlives the owner's shutdown by
    the full request deadline.
    """

    event = _STOP_EVENT.get()
    if event is None:
        return queue.get(timeout=timeout)
    deadline = time.monotonic() + max(0.0, timeout)
    while True:
        if event.is_set():
            raise Empty
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise Empty
        try:
            return queue.get(timeout=min(remaining, _STOP_POLL_SECONDS))
        except Empty:
            continue
