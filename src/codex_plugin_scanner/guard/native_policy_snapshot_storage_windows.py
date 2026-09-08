"""Windows handle readers for native policy snapshot state."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .native_policy_snapshot_constants import (
    _MAX_STATE_BYTES,
    POLICY_SNAPSHOT_MAX_BYTES,
    NativePolicySnapshotError,
)


def _snapshot_api() -> Any:
    """Resolve façade hooks lazily to preserve the legacy test seams."""

    from . import native_policy_snapshot

    return native_policy_snapshot


def _windows_read_snapshot_bytes(
    path: Path,
    *,
    maximum_bytes: int = POLICY_SNAPSHOT_MAX_BYTES,
) -> bytes | None:
    """Read one cache object from a single verified non-reparse handle."""

    import ctypes
    from ctypes import wintypes

    api = _snapshot_api()
    try:
        kernel32, handle, information = api._windows_open_handle(
            path,
            directory=False,
            share_delete=True,
        )
    except FileNotFoundError:
        return None
    try:
        owner_sid = api._windows_owner_sid()
        api._windows_verify_private_dacl(handle, owner_sid=owner_sid, directory=False)
        expected_size = (int(information.nFileSizeHigh) << 32) | int(information.nFileSizeLow)
        if expected_size <= 0 or expected_size > maximum_bytes:
            raise NativePolicySnapshotError("native_policy_snapshot_cache_invalid")
        read_file = kernel32.ReadFile
        read_file.argtypes = [
            wintypes.HANDLE,
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
            ctypes.c_void_p,
        ]
        read_file.restype = wintypes.BOOL
        buffer = (ctypes.c_ubyte * (maximum_bytes + 1))()
        total = 0
        while total <= maximum_bytes:
            request_size = min(64 * 1024, maximum_bytes + 1 - total)
            if request_size <= 0:
                break
            count = wintypes.DWORD()
            if not read_file(
                handle,
                ctypes.byref(buffer, total),
                request_size,
                ctypes.byref(count),
                None,
            ):
                raise NativePolicySnapshotError("native_policy_snapshot_cache_read_failed")
            chunk_size = int(count.value)
            if chunk_size < 0 or chunk_size > request_size:
                raise NativePolicySnapshotError("native_policy_snapshot_cache_read_failed")
            if chunk_size == 0:
                break
            total += chunk_size
        if total != expected_size or total > maximum_bytes:
            raise NativePolicySnapshotError("native_policy_snapshot_cache_invalid")
        return bytes(buffer[:total])
    finally:
        api._windows_close_handle(kernel32, handle)


def _windows_read_generation_state_bytes(path: Path) -> bytes | None:
    """Read generation state through one verified non-reparse handle."""

    import ctypes
    from ctypes import wintypes

    api = _snapshot_api()
    try:
        kernel32, handle, information = api._windows_open_handle(
            path,
            directory=False,
            share_delete=True,
        )
    except FileNotFoundError:
        return None
    try:
        owner_sid = api._windows_owner_sid()
        api._windows_verify_private_dacl(handle, owner_sid=owner_sid, directory=False)
        expected_size = (int(information.nFileSizeHigh) << 32) | int(information.nFileSizeLow)
        if expected_size <= 0 or expected_size > _MAX_STATE_BYTES:
            raise NativePolicySnapshotError("native_policy_snapshot_generation_state_invalid")
        read_file = kernel32.ReadFile
        read_file.argtypes = [
            wintypes.HANDLE,
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
            ctypes.c_void_p,
        ]
        read_file.restype = wintypes.BOOL
        buffer = (ctypes.c_ubyte * (_MAX_STATE_BYTES + 1))()
        total = 0
        while total <= _MAX_STATE_BYTES:
            request_size = min(64 * 1024, _MAX_STATE_BYTES + 1 - total)
            if request_size <= 0:
                break
            count = wintypes.DWORD()
            if not read_file(
                handle,
                ctypes.byref(buffer, total),
                request_size,
                ctypes.byref(count),
                None,
            ):
                raise NativePolicySnapshotError("native_policy_snapshot_generation_state_read_failed")
            chunk_size = int(count.value)
            if chunk_size < 0 or chunk_size > request_size:
                raise NativePolicySnapshotError("native_policy_snapshot_generation_state_read_failed")
            if chunk_size == 0:
                break
            total += chunk_size
        if total != expected_size or total > _MAX_STATE_BYTES:
            raise NativePolicySnapshotError("native_policy_snapshot_generation_state_invalid")
        return bytes(buffer[:total])
    finally:
        api._windows_close_handle(kernel32, handle)
