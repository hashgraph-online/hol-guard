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
from pathlib import Path

from .fork_safety import forget_in_child

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


# A child forked while a thread held a lock would inherit it held forever.
forget_in_child(_PATH_LOCKS)

__all__ = ["process_lock_for"]
