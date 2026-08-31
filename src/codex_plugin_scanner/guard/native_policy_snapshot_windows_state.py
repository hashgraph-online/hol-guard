"""Windows private directory provisioning."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .native_policy_snapshot_constants import _WINDOWS_ERROR_ALREADY_EXISTS, NativePolicySnapshotError


def _snapshot_api() -> Any:
    """Resolve façade hooks lazily, preserving established monkeypatch seams."""

    from . import native_policy_snapshot

    return native_policy_snapshot


def _windows_ensure_private_directory(path: Path) -> None:
    import ctypes
    from ctypes import wintypes

    api = _snapshot_api()
    created = False
    try:
        with api._windows_private_descriptor(True) as (_advapi32, descriptor, dacl, owner_sid):
            kernel32 = api._windows_dll("kernel32")
            create_directory = kernel32.CreateDirectoryW
            create_directory.argtypes = [wintypes.LPCWSTR, ctypes.c_void_p]
            create_directory.restype = wintypes.BOOL
            security_attributes_type = api._windows_security_attributes_type()
            security_attributes = security_attributes_type(
                ctypes.sizeof(security_attributes_type), descriptor, wintypes.BOOL(False)
            )
            if create_directory(str(path), ctypes.byref(security_attributes)):
                created = True
            elif ctypes.get_last_error() != _WINDOWS_ERROR_ALREADY_EXISTS:
                raise NativePolicySnapshotError("native_policy_windows_state_directory_create_failed")
            kernel32, handle, _information = api._windows_open_handle(
                path,
                directory=True,
                descriptor=descriptor if created else None,
            )
            try:
                if created:
                    api._windows_apply_private_dacl(kernel32, handle, descriptor, dacl, True)
                api._windows_verify_private_dacl(handle, owner_sid=owner_sid, directory=True)
            finally:
                api._windows_close_handle(kernel32, handle)
    except NativePolicySnapshotError:
        raise
    except (OSError, RuntimeError, TypeError, ValueError) as error:
        raise NativePolicySnapshotError("native_policy_windows_state_directory_invalid") from error
