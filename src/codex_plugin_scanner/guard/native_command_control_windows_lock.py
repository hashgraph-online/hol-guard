"""Windows byte-zero leases on an already admitted authority file handle."""

from __future__ import annotations

import ctypes
from typing import Any

_LOCKFILE_FAIL_IMMEDIATELY = 0x00000001
_LOCKFILE_EXCLUSIVE_LOCK = 0x00000002


class _Overlapped(ctypes.Structure):
    # ULONG_PTR is pointer-sized; Windows DWORD is 32 bits on both ABIs.
    _fields_ = [
        ("Internal", ctypes.c_size_t),
        ("InternalHigh", ctypes.c_size_t),
        ("Offset", ctypes.c_uint32),
        ("OffsetHigh", ctypes.c_uint32),
        ("hEvent", ctypes.c_void_p),
    ]


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


def try_lock_authority_file(descriptor: int, *, shared: bool) -> None:
    """Take a nonblocking lease overlapping Rust fs2's whole-file lease.

    CRT LK_NBRLCK is an alias for exclusive LK_NBLCK, so it cannot express
    the shared publisher/reviewer lease. LockFileEx without EXCLUSIVE can.
    The synchronous handle and FAIL_IMMEDIATELY prevent a pending operation
    from retaining this stack-owned OVERLAPPED after the function returns.
    """

    flags = _LOCKFILE_FAIL_IMMEDIATELY | (0 if shared else _LOCKFILE_EXCLUSIVE_LOCK)
    overlapped = _Overlapped()
    if not _kernel32().LockFileEx(_os_handle(descriptor), flags, 0, 1, 0, ctypes.byref(overlapped)):
        raise _last_error()


def unlock_authority_file(descriptor: int) -> None:
    """Release exactly the byte-zero range acquired through the retained fd."""

    overlapped = _Overlapped()
    if not _kernel32().UnlockFileEx(_os_handle(descriptor), 0, 1, 0, ctypes.byref(overlapped)):
        raise _last_error()
