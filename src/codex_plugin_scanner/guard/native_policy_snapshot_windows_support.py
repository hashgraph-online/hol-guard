"""Windows-safe state directory and security descriptor helpers."""

from __future__ import annotations

import os
import re
import stat
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from .native_policy_snapshot_constants import (
    _WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT,
    _WINDOWS_SYSTEM_SID,
    NATIVE_RUNTIME_STATE_DIRECTORY,
    NativePolicySnapshotError,
)


def _snapshot_api() -> Any:
    """Resolve the compatibility façade only after package initialization."""

    from . import native_policy_snapshot

    return native_policy_snapshot


def _windows_path_has_reparse_component(path: Path) -> bool:
    """Reject final and parent reparse points before traversing a state path."""

    for candidate in (path, *path.parents):
        try:
            metadata = candidate.lstat()
        except FileNotFoundError:
            continue
        file_attributes: object = getattr(metadata, "st_file_attributes", 0)
        if candidate.is_symlink() or (
            isinstance(file_attributes, int) and bool(file_attributes & _WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT)
        ):
            return True
    return False


def _runtime_state_directory(guard_home: Path) -> Path:
    api = _snapshot_api()
    api._private_guard_home(guard_home)
    state_dir = guard_home / NATIVE_RUNTIME_STATE_DIRECTORY
    if os.name == "nt":
        api._windows_ensure_private_directory(state_dir)
        return state_dir
    try:
        metadata = state_dir.lstat()
    except FileNotFoundError:
        try:
            state_dir.mkdir(mode=0o700)
        except FileExistsError:
            metadata = state_dir.lstat()
        else:
            metadata = state_dir.lstat()
    except OSError as error:
        raise NativePolicySnapshotError("native_policy_runtime_state_invalid") from error
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise NativePolicySnapshotError("native_policy_runtime_state_invalid")
    if os.name != "nt" and (metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) & 0o077):
        raise NativePolicySnapshotError("native_policy_runtime_state_not_private")
    if os.name != "nt":
        try:
            state_dir.chmod(0o700)
        except OSError as error:
            raise NativePolicySnapshotError("native_policy_runtime_state_not_private") from error
    return state_dir


def _windows_dll(name: str) -> Any:
    import ctypes

    win_dll = getattr(ctypes, "WinDLL", None)
    if not callable(win_dll):
        raise NativePolicySnapshotError("native_policy_windows_acl_unavailable")
    try:
        return win_dll(name, use_last_error=True)
    except (OSError, RuntimeError, TypeError, ValueError) as error:
        raise NativePolicySnapshotError("native_policy_windows_acl_unavailable") from error


def _windows_owner_sid() -> str:
    from .mdm.device_key_native import windows_current_user_sid

    try:
        sid = windows_current_user_sid()
    except (OSError, RuntimeError, TypeError, ValueError) as error:
        raise NativePolicySnapshotError("native_policy_windows_owner_sid_failed") from error
    if re.fullmatch(r"S-[0-9]+(?:-[0-9]+)+", sid) is None:
        raise NativePolicySnapshotError("native_policy_windows_owner_sid_invalid")
    return sid


@contextmanager
def _windows_private_descriptor(directory: bool) -> Iterator[tuple[Any, Any, Any, str]]:
    import ctypes
    from ctypes import wintypes

    advapi32 = _windows_dll("advapi32")
    kernel32 = _windows_dll("kernel32")
    owner_sid = _windows_owner_sid()
    inheritance = "OICI" if directory else ""
    owner_ace = f"(A;{inheritance};FA;;;{owner_sid})"
    system_ace = "" if owner_sid == _WINDOWS_SYSTEM_SID else f"(A;{inheritance};FA;;;{_WINDOWS_SYSTEM_SID})"
    sddl = f"O:{owner_sid}D:P{owner_ace}{system_ace}"
    descriptor = ctypes.c_void_p()
    descriptor_size = wintypes.DWORD()
    convert = advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW
    convert.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(wintypes.DWORD),
    ]
    convert.restype = wintypes.BOOL
    if not convert(sddl, 1, ctypes.byref(descriptor), ctypes.byref(descriptor_size)):
        raise NativePolicySnapshotError("native_policy_windows_acl_build_failed")
    local_free = kernel32.LocalFree
    local_free.argtypes = [ctypes.c_void_p]
    local_free.restype = ctypes.c_void_p
    try:
        dacl_present = wintypes.BOOL()
        dacl = ctypes.c_void_p()
        dacl_defaulted = wintypes.BOOL()
        get_dacl = advapi32.GetSecurityDescriptorDacl
        get_dacl.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(wintypes.BOOL),
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.POINTER(wintypes.BOOL),
        ]
        get_dacl.restype = wintypes.BOOL
        if (
            not get_dacl(
                descriptor,
                ctypes.byref(dacl_present),
                ctypes.byref(dacl),
                ctypes.byref(dacl_defaulted),
            )
            or not dacl_present.value
            or not dacl
        ):
            raise NativePolicySnapshotError("native_policy_windows_acl_build_failed")
        yield advapi32, descriptor, dacl, owner_sid
    finally:
        local_free(descriptor)


def _windows_file_information_type() -> Any:
    import ctypes
    from ctypes import wintypes

    class ByHandleFileInformation(ctypes.Structure):
        _fields_ = [
            ("dwFileAttributes", wintypes.DWORD),
            ("ftCreationTime", wintypes.FILETIME),
            ("ftLastAccessTime", wintypes.FILETIME),
            ("ftLastWriteTime", wintypes.FILETIME),
            ("dwVolumeSerialNumber", wintypes.DWORD),
            ("nFileSizeHigh", wintypes.DWORD),
            ("nFileSizeLow", wintypes.DWORD),
            ("nNumberOfLinks", wintypes.DWORD),
            ("nFileIndexHigh", wintypes.DWORD),
            ("nFileIndexLow", wintypes.DWORD),
        ]

    return ByHandleFileInformation


def _windows_security_attributes_type() -> Any:
    import ctypes
    from ctypes import wintypes

    class SecurityAttributes(ctypes.Structure):
        _fields_ = [
            ("nLength", wintypes.DWORD),
            ("lpSecurityDescriptor", ctypes.c_void_p),
            ("bInheritHandle", wintypes.BOOL),
        ]

    return SecurityAttributes
