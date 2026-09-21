"""Deadline-bounded writes for the Rust resident-client stream."""

from __future__ import annotations

import os
import selectors
import threading
import time
from contextlib import suppress


def _write_frame_nonblocking(
    stdin: object,
    frame: bytes,
    *,
    deadline_monotonic: float,
) -> bool | None:
    """Write one frame without allowing a full child pipe to block.

    ``None`` means this platform's pipe object cannot be driven through a
    non-blocking file descriptor; callers use the stoppable worker fallback
    for that case. A boolean result is a completed or deadline-bounded
    write attempt.

    Windows anonymous pipes are not sockets. ``select()`` rejects them with
    WSAENOTSOCK after ``fileno()`` and ``set_blocking()`` already succeeded,
    so the selector path must not run there.
    """

    if os.name == "nt":
        return None
    fileno = getattr(stdin, "fileno", None)
    if not callable(fileno):
        return None
    descriptor: int | None = None
    selector: selectors.BaseSelector | None = None
    try:
        candidate = fileno()
        if not isinstance(candidate, int):
            return None
        descriptor = candidate
        os.set_blocking(descriptor, False)
        selector = selectors.DefaultSelector()
        selector.register(descriptor, selectors.EVENT_WRITE)
    except (OSError, ValueError, TypeError):
        if selector is not None:
            selector.close()
        if descriptor is not None:
            with suppress(OSError, ValueError):
                os.set_blocking(descriptor, True)
        return None
    assert descriptor is not None and selector is not None

    offset = 0
    try:
        while offset < len(frame):
            remaining = deadline_monotonic - time.monotonic()
            if remaining <= 0:
                return False
            try:
                ready = selector.select(timeout=remaining)
            except (OSError, ValueError):
                return False
            if not ready:
                return False
            try:
                written = os.write(descriptor, frame[offset:])
            except BlockingIOError:
                continue
            except (OSError, ValueError):
                return False
            if written <= 0:
                return False
            offset += written
        return True
    finally:
        selector.close()


def _write_frame_with_stoppable_worker(
    stdin: object,
    frame: bytes,
    *,
    deadline_monotonic: float,
) -> bool:
    """Bound platforms whose anonymous pipes are not selector-friendly."""

    finished = threading.Event()
    failed = False

    def write() -> None:
        nonlocal failed
        try:
            writer = getattr(stdin, "write")  # noqa: B009
            flush = getattr(stdin, "flush")  # noqa: B009
            writer(frame)
            flush()
        except Exception:
            failed = True
        finally:
            finished.set()

    worker = threading.Thread(target=write, name="hol-guard-native-client-writer", daemon=True)
    worker.start()
    remaining = deadline_monotonic - time.monotonic()
    if remaining <= 0 or not finished.wait(timeout=remaining):
        # Closing the descriptor wakes a blocked BufferedWriter on the
        # platforms where selector-based pipe writes are unavailable.
        close = getattr(stdin, "close", None)
        if callable(close):
            with suppress(Exception):
                close()
        worker.join(timeout=0.05)
        return False
    worker.join()
    return not failed


def write_frame(stdin: object, frame: bytes, *, deadline_monotonic: float) -> bool:
    """Write a complete frame within a monotonic deadline."""

    nonblocking_result = _write_frame_nonblocking(
        stdin,
        frame,
        deadline_monotonic=deadline_monotonic,
    )
    if nonblocking_result is not None:
        return nonblocking_result
    return _write_frame_with_stoppable_worker(
        stdin,
        frame,
        deadline_monotonic=deadline_monotonic,
    )


__all__ = ["write_frame"]
