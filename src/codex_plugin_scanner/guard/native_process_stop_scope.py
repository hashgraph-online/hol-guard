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
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar

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
