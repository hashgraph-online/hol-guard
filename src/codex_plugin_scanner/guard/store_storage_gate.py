"""Cross-process Guard storage access gate, re-entrant per thread and home.

The gate is a one-byte lock on ``<guard home>/storage-access.lock``. A thread
that already holds it for a home nests every further hold for that same home,
whichever ``GuardStore`` instance asks: a nested store (for example the one
that provisions the resident verifier key inside a native store call) must
not wait on its own thread's hold. POSIX ``flock`` happened to admit a nested
shared hold on a second descriptor, but Windows ``msvcrt.locking`` has no
shared mode, so the nested hold waited out the whole deadline and failed.
Holds from other threads and processes still contend on the file lock.
"""

from __future__ import annotations

import os
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import IO

from .sqlite_tuning import sqlite_connect_timeout_seconds

_LOCK_FILE_NAME = "storage-access.lock"
_LOCAL = threading.local()


class _Hold:
    __slots__ = ("depth", "exclusive")

    def __init__(self, *, exclusive: bool) -> None:
        self.depth = 1
        self.exclusive = exclusive


def _holds() -> dict[str, _Hold]:
    holds = getattr(_LOCAL, "holds", None)
    if holds is None:
        holds = {}
        _LOCAL.holds = holds
    return holds


def _gate_key(lock_path: Path) -> str:
    return os.path.normcase(os.path.abspath(lock_path))


def _lock(handle: IO[bytes], *, exclusive: bool) -> None:
    """Take the gate without blocking; raises ``OSError`` when it is held."""

    if os.name == "nt":
        import msvcrt

        handle.seek(0)
        if not handle.read(1):
            handle.write(b"0")
            handle.flush()
        handle.seek(0)
        mode = msvcrt.LK_NBLCK if exclusive else msvcrt.LK_NBRLCK
        msvcrt.locking(handle.fileno(), mode, 1)
    else:
        import fcntl

        mode = fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH
        fcntl.flock(handle.fileno(), mode | fcntl.LOCK_NB)


def _unlock(handle: IO[bytes]) -> None:
    if os.name == "nt":
        import msvcrt

        handle.seek(0)
        msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
    else:
        import fcntl

        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


@contextmanager
def _nested(hold: _Hold) -> Iterator[None]:
    hold.depth += 1
    try:
        yield
    finally:
        hold.depth -= 1


@contextmanager
def _owned(key: str, *, exclusive: bool) -> Iterator[None]:
    holds = _holds()
    holds[key] = _Hold(exclusive=exclusive)
    try:
        yield
    finally:
        holds.pop(key, None)


@contextmanager
def hold_storage_gate(guard_home: Path, *, exclusive: bool) -> Iterator[None]:
    """Hold the gate until the block exits, waiting up to the connect timeout."""

    lock_path = guard_home / _LOCK_FILE_NAME
    key = _gate_key(lock_path)
    hold = _holds().get(key)
    if hold is not None and hold.depth > 0:
        if exclusive and not hold.exclusive:
            raise RuntimeError("Cannot upgrade an active Guard storage read gate.")
        with _nested(hold):
            yield
        return
    deadline = time.monotonic() + sqlite_connect_timeout_seconds()
    with lock_path.open("a+b") as handle:
        while True:
            try:
                _lock(handle, exclusive=exclusive)
                break
            except OSError:
                if time.monotonic() >= deadline:
                    raise TimeoutError("Timed out waiting for Guard storage access.") from None
                time.sleep(0.01)
        try:
            with _owned(key, exclusive=exclusive):
                yield
        finally:
            _unlock(handle)


@contextmanager
def try_hold_storage_gate(guard_home: Path, *, exclusive: bool) -> Iterator[bool]:
    """Attempt the gate once without blocking; yields whether it is held.

    Nesting under this thread's hold for the same home yields True, while
    upgrading a shared hold to exclusive yields False instead of raising.
    """

    lock_path = guard_home / _LOCK_FILE_NAME
    key = _gate_key(lock_path)
    hold = _holds().get(key)
    if hold is not None and hold.depth > 0:
        if exclusive and not hold.exclusive:
            yield False
            return
        with _nested(hold):
            yield True
        return
    handle: IO[bytes] | None = None
    try:
        acquired = False
        try:
            handle = lock_path.open("a+b")
            _lock(handle, exclusive=exclusive)
            acquired = True
        except OSError:
            pass
        if not acquired or handle is None:
            yield False
            return
        try:
            with _owned(key, exclusive=exclusive):
                yield True
        finally:
            _unlock(handle)
    finally:
        if handle is not None:
            handle.close()
