"""Shared ordinary access and exclusive recovery for the local store."""

from __future__ import annotations

import ctypes
import errno
import os
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path


class StorageAccessTimeoutError(TimeoutError):
    """The existing bounded storage admission budget expired."""


class _Overlapped(ctypes.Structure):
    _fields_ = [
        ("internal", ctypes.c_size_t),
        ("internal_high", ctypes.c_size_t),
        ("offset", ctypes.c_uint32),
        ("offset_high", ctypes.c_uint32),
        ("event", ctypes.c_void_p),
    ]


class _WindowsStorageLock:
    def __init__(self, handle: int) -> None:
        self._handle = handle
        self._overlapped = _Overlapped()
        self._library = ctypes.WinDLL("kernel32", use_last_error=True)
        self._library.LockFileEx.argtypes = [
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.POINTER(_Overlapped),
        ]
        self._library.LockFileEx.restype = ctypes.c_int
        self._library.UnlockFileEx.argtypes = [
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.POINTER(_Overlapped),
        ]
        self._library.UnlockFileEx.restype = ctypes.c_int

    def acquire(self, *, exclusive: bool) -> None:
        # CRT LK_NBRLCK is exclusive too. LockFileEx without flag 2 is shared.
        # Flag 1 prevents an unbounded native wait; the caller owns the deadline.
        flags = 1 | (2 if exclusive else 0)
        if not self._library.LockFileEx(
            ctypes.c_void_p(self._handle),
            flags,
            0,
            1,
            0,
            ctypes.byref(self._overlapped),
        ):
            code = ctypes.get_last_error()
            if code == 33:  # ERROR_LOCK_VIOLATION: another handle owns the range.
                raise BlockingIOError(errno.EAGAIN, "Storage access is already held.")
            raise ctypes.WinError(code)

    def release(self) -> None:
        if not self._library.UnlockFileEx(
            ctypes.c_void_p(self._handle),
            0,
            1,
            0,
            ctypes.byref(self._overlapped),
        ):
            raise ctypes.WinError(ctypes.get_last_error())


def _windows_lock(descriptor: int) -> _WindowsStorageLock:
    import msvcrt

    return _WindowsStorageLock(msvcrt.get_osfhandle(descriptor))


@contextmanager
def hold_storage_file_lock(
    path: Path, *, exclusive: bool, timeout_seconds: float, deadline_monotonic: float | None = None
) -> Iterator[None]:
    deadline = time.monotonic() + timeout_seconds
    if deadline_monotonic is not None:
        deadline = min(deadline, deadline_monotonic)
        if time.monotonic() >= deadline:
            raise StorageAccessTimeoutError("Timed out waiting for Guard storage access.")
    with path.open("a+b") as handle:
        windows_lock = _windows_lock(handle.fileno()) if os.name == "nt" else None
        # Locking beyond EOF is supported. Do not initialize a byte through a
        # second handle: on Windows that write conflicts with existing readers.
        while True:
            if deadline_monotonic is not None and time.monotonic() >= deadline:
                raise StorageAccessTimeoutError("Timed out waiting for Guard storage access.")
            try:
                if windows_lock is not None:
                    windows_lock.acquire(exclusive=exclusive)
                else:
                    import fcntl

                    mode = fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH
                    fcntl.flock(handle.fileno(), mode | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise StorageAccessTimeoutError("Timed out waiting for Guard storage access.") from None
                time.sleep(min(0.01, remaining))
        try:
            yield
        finally:
            if windows_lock is not None:
                windows_lock.release()
            else:
                import fcntl

                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
