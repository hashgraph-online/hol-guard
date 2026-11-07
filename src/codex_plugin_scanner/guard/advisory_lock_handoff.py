"""In-process hand-off for Guard's advisory file locks.

A file lock that is busy is retried on a poll interval, so a thread waiting
behind another thread of the same process only notices the release on its
next poll. When several threads queue for one lock, as parallel Cloud Review
decisions do for the OAuth credential lock, each hand-off waits out part of
that interval. Threads of one process first queue on a ``threading.Lock`` for
the same path, which wakes the next waiter as soon as the holder releases.
The file lock still serializes against other processes.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from pathlib import Path

from .fork_safety import forget_in_child
from .store_base import _acquire_advisory_file_lock, _release_advisory_file_lock

_PATH_LOCKS: dict[str, threading.Lock] = {}
_PATH_LOCKS_GUARD = threading.Lock()


def process_lock_for(path: Path) -> threading.Lock:
    key = str(path.absolute())
    with _PATH_LOCKS_GUARD:
        lock = _PATH_LOCKS.get(key)
        if lock is None:
            lock = threading.Lock()
            _PATH_LOCKS[key] = lock
        return lock


@contextmanager
def hold_advisory_file_lock(
    *,
    path: Path,
    timeout_seconds: float,
    poll_seconds: float,
    timeout_message: str,
    timeout_error: type[TimeoutError] = TimeoutError,
) -> Iterator[None]:
    deadline = time.monotonic() + max(timeout_seconds, 0.0)
    # Threads of this process queue here first, so a release wakes the
    # next one at once instead of on its next file-lock poll.
    process_lock = process_lock_for(path)
    if not process_lock.acquire(timeout=max(deadline - time.monotonic(), 0.0)):
        raise timeout_error(timeout_message)
    try:
        with path.open("a+b") as handle:
            while True:
                try:
                    _acquire_advisory_file_lock(handle)
                    break
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        raise timeout_error(timeout_message) from None
                    time.sleep(poll_seconds)
            try:
                yield
            finally:
                with suppress(OSError):
                    _release_advisory_file_lock(handle)
    finally:
        process_lock.release()


# A child forked while a thread held a lock would inherit it held forever.
forget_in_child(_PATH_LOCKS)

__all__ = ["hold_advisory_file_lock", "process_lock_for"]
