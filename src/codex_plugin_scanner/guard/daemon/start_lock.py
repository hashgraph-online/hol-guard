"""Reentrant cross-process start lock for the Guard daemon."""

from __future__ import annotations

import threading
import time
from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path

from ..mdm.file_lock import release_file_lock
from .file_locking import lock_daemon_file, try_lock_daemon_file

_POLL_INTERVAL_SECONDS = 0.1
_THREAD_LOCKS: dict[str, threading.Lock] = {}
_THREAD_LOCKS_GUARD = threading.Lock()
_THREAD_DEPTHS: dict[tuple[int, str], int] = {}


@contextmanager
def guard_daemon_start_lock(guard_home: Path, *, deadline: float | None = None) -> Generator[None]:
    """Serialize daemon replacement while allowing a lock-owning repair to restart."""

    lock_key = str(guard_home.resolve())
    depth_key = (threading.get_ident(), lock_key)
    with _THREAD_LOCKS_GUARD:
        thread_lock = _THREAD_LOCKS.setdefault(lock_key, threading.Lock())
        nested_depth = _THREAD_DEPTHS.get(depth_key, 0)
        if nested_depth:
            _THREAD_DEPTHS[depth_key] = nested_depth + 1
    if nested_depth:
        try:
            yield
        finally:
            with _THREAD_LOCKS_GUARD:
                remaining_depth = _THREAD_DEPTHS[depth_key] - 1
                if remaining_depth:
                    _THREAD_DEPTHS[depth_key] = remaining_depth
                else:
                    _ = _THREAD_DEPTHS.pop(depth_key, None)
        return
    if deadline is None:
        thread_lock.acquire()
    else:
        acquired = thread_lock.acquire(timeout=max(0.0, deadline - time.monotonic()))
        if not acquired:
            raise RuntimeError("Timed out waiting to start the Guard daemon.")
    try:
        lock_path = guard_home / "daemon-start.lock"
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        with lock_path.open("a+b") as handle:
            if deadline is None:
                lock_daemon_file(handle, poll_interval=_POLL_INTERVAL_SECONDS)
            else:
                while not try_lock_daemon_file(handle):
                    if time.monotonic() >= deadline:
                        raise RuntimeError("Timed out waiting to start the Guard daemon.")
                    time.sleep(min(_POLL_INTERVAL_SECONDS, max(0.0, deadline - time.monotonic())))
            try:
                with _THREAD_LOCKS_GUARD:
                    _THREAD_DEPTHS[depth_key] = 1
                yield
            finally:
                with _THREAD_LOCKS_GUARD:
                    _ = _THREAD_DEPTHS.pop(depth_key, None)
                release_file_lock(handle)
    finally:
        thread_lock.release()


__all__ = ["guard_daemon_start_lock"]
