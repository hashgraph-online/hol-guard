"""Windows LockFileEx leases on an already opened file handle.

Authority files take a byte-zero lease. The storage gate takes the whole
file, the same range Rust ``fs2`` locks, so the two sides contend on one
range instead of merely overlapping.
"""

from __future__ import annotations

import ctypes
import functools
from typing import Any

_LOCKFILE_FAIL_IMMEDIATELY = 0x00000001
_LOCKFILE_EXCLUSIVE_LOCK = 0x00000002
# fs2 locks offset 0 for the largest length LockFileEx accepts.
_WHOLE_FILE = 0xFFFFFFFF


class _Overlapped(ctypes.Structure):
    # ULONG_PTR is pointer-sized; Windows DWORD is 32 bits on both ABIs.
    _fields_ = [
        ("Internal", ctypes.c_size_t),
        ("InternalHigh", ctypes.c_size_t),
        ("Offset", ctypes.c_uint32),
        ("OffsetHigh", ctypes.c_uint32),
        ("hEvent", ctypes.c_void_p),
    ]


@functools.cache
def _kernel32() -> Any:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.LockFileEx.argtypes = [
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.POINTER(_Overlapped),
    ]
    kernel32.LockFileEx.restype = ctypes.c_int
    kernel32.UnlockFileEx.argtypes = [
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.POINTER(_Overlapped),
    ]
    kernel32.UnlockFileEx.restype = ctypes.c_int
    return kernel32


def _os_handle(descriptor: int) -> int:
    import msvcrt

    return msvcrt.get_osfhandle(descriptor)


def _last_error() -> OSError:
    return ctypes.WinError(ctypes.get_last_error())


def _try_lock(descriptor: int, *, shared: bool, low: int, high: int) -> None:
    flags = _LOCKFILE_FAIL_IMMEDIATELY | (0 if shared else _LOCKFILE_EXCLUSIVE_LOCK)
    overlapped = _Overlapped()
    if not _kernel32().LockFileEx(_os_handle(descriptor), flags, 0, low, high, ctypes.byref(overlapped)):
        raise _last_error()


def _unlock(descriptor: int, *, low: int, high: int) -> None:
    overlapped = _Overlapped()
    if not _kernel32().UnlockFileEx(_os_handle(descriptor), 0, low, high, ctypes.byref(overlapped)):
        raise _last_error()


def try_lock_authority_file(descriptor: int, *, shared: bool) -> None:
    """Take a nonblocking lease overlapping Rust fs2's whole-file lease.

    CRT LK_NBRLCK is an alias for exclusive LK_NBLCK, so it cannot express
    the shared publisher/reviewer lease. LockFileEx without EXCLUSIVE can.
    The synchronous handle and FAIL_IMMEDIATELY prevent a pending operation
    from retaining this stack-owned OVERLAPPED after the function returns.
    """

    _try_lock(descriptor, shared=shared, low=1, high=0)


def unlock_authority_file(descriptor: int) -> None:
    """Release exactly the byte-zero range acquired through the retained fd."""

    _unlock(descriptor, low=1, high=0)


def try_lock_whole_file(descriptor: int, *, shared: bool) -> None:
    """Take a nonblocking lease on exactly the range Rust fs2 locks."""

    _try_lock(descriptor, shared=shared, low=_WHOLE_FILE, high=_WHOLE_FILE)


def unlock_whole_file(descriptor: int) -> None:
    """Release the whole-file range acquired through the retained fd."""

    _unlock(descriptor, low=_WHOLE_FILE, high=_WHOLE_FILE)
