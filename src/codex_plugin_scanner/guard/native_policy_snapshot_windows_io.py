"""Windows handle primitives for native policy state."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .native_policy_snapshot_constants import (
    _WINDOWS_CREATE_NEW,
    _WINDOWS_ERROR_ALREADY_EXISTS,
    _WINDOWS_ERROR_FILE_EXISTS,
    _WINDOWS_ERROR_FILE_NOT_FOUND,
    _WINDOWS_ERROR_PATH_NOT_FOUND,
    _WINDOWS_FILE_ATTRIBUTE_DIRECTORY,
    _WINDOWS_FILE_ATTRIBUTE_NORMAL,
    _WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT,
    _WINDOWS_FILE_FLAG_BACKUP_SEMANTICS,
    _WINDOWS_FILE_FLAG_OPEN_REPARSE_POINT,
    _WINDOWS_FILE_FLAG_WRITE_THROUGH,
    _WINDOWS_FILE_SHARE_READ,
    _WINDOWS_FILE_SHARE_WRITE,
    _WINDOWS_FILE_TYPE_DISK,
    _WINDOWS_GENERIC_READ,
    _WINDOWS_GENERIC_WRITE,
    _WINDOWS_OPEN_EXISTING,
    _WINDOWS_SE_FILE_OBJECT,
    _WINDOWS_SECURITY_INFORMATION,
    _WINDOWS_WRITE_DAC,
    NativePolicySnapshotError,
)


def _snapshot_api() -> Any:
    """Resolve façade hooks lazily, preserving established monkeypatch seams."""

    from . import native_policy_snapshot

    return native_policy_snapshot


def _windows_open_handle(
    path: Path,
    *,
    directory: bool,
    create_new: bool = False,
    share_write: bool = False,
    descriptor: Any | None = None,
) -> tuple[Any, Any, Any]:
    """Open/create one non-reparse Windows object while denying deletion."""

    import ctypes
    from ctypes import wintypes

    api = _snapshot_api()
    kernel32 = api._windows_dll("kernel32")
    create_file = kernel32.CreateFileW
    create_file.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    create_file.restype = wintypes.HANDLE
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = [wintypes.HANDLE]
    close_handle.restype = wintypes.BOOL
    get_information = kernel32.GetFileInformationByHandle
    information_type = api._windows_file_information_type()
    get_information.argtypes = [wintypes.HANDLE, ctypes.POINTER(information_type)]
    get_information.restype = wintypes.BOOL
    get_file_type = kernel32.GetFileType
    get_file_type.argtypes = [wintypes.HANDLE]
    get_file_type.restype = wintypes.DWORD
    attributes = _WINDOWS_FILE_ATTRIBUTE_NORMAL
    flags = _WINDOWS_FILE_FLAG_OPEN_REPARSE_POINT
    if directory:
        flags |= _WINDOWS_FILE_FLAG_BACKUP_SEMANTICS
        desired_access = _WINDOWS_GENERIC_READ
        share_mode = _WINDOWS_FILE_SHARE_READ | _WINDOWS_FILE_SHARE_WRITE
    else:
        desired_access = _WINDOWS_GENERIC_READ | (_WINDOWS_GENERIC_WRITE if create_new else 0)
        share_mode = _WINDOWS_FILE_SHARE_READ
        if share_write:
            share_mode |= _WINDOWS_FILE_SHARE_WRITE
    if descriptor is not None:
        # SetSecurityInfo needs WRITE_DAC on the handle. Ownership is left
        # unchanged so existing administrator- or SYSTEM-owned state can be
        # hardened without requiring WRITE_OWNER.
        desired_access |= _WINDOWS_WRITE_DAC
    if create_new:
        flags |= _WINDOWS_FILE_FLAG_WRITE_THROUGH
        disposition = _WINDOWS_CREATE_NEW
    else:
        disposition = _WINDOWS_OPEN_EXISTING
    security_attributes = None
    if descriptor is not None:
        security_attributes_type = api._windows_security_attributes_type()
        security_attributes = security_attributes_type(
            ctypes.sizeof(security_attributes_type), descriptor, wintypes.BOOL(False)
        )
    handle = create_file(
        str(path),
        desired_access,
        share_mode,
        ctypes.byref(security_attributes) if security_attributes is not None else None,
        disposition,
        attributes | flags,
        None,
    )
    invalid_handle = ctypes.c_void_p(-1).value
    handle_value = getattr(handle, "value", handle)
    if handle is None or handle_value == invalid_handle:
        error_code = ctypes.get_last_error()
        if error_code in {_WINDOWS_ERROR_FILE_NOT_FOUND, _WINDOWS_ERROR_PATH_NOT_FOUND}:
            raise FileNotFoundError(str(path))
        if create_new and error_code in {_WINDOWS_ERROR_FILE_EXISTS, _WINDOWS_ERROR_ALREADY_EXISTS}:
            raise FileExistsError(str(path))
        raise NativePolicySnapshotError("native_policy_windows_path_open_failed")
    try:
        information = information_type()
        if not get_information(handle, ctypes.byref(information)):
            raise NativePolicySnapshotError("native_policy_windows_path_stat_failed")
        file_attributes = int(information.dwFileAttributes)
        expected_directory = bool(file_attributes & _WINDOWS_FILE_ATTRIBUTE_DIRECTORY)
        if (
            bool(directory) != expected_directory
            or file_attributes & _WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT
            or get_file_type(handle) != _WINDOWS_FILE_TYPE_DISK
        ):
            raise NativePolicySnapshotError("native_policy_windows_path_invalid")
        return kernel32, handle, information
    except BaseException:
        close_handle(handle)
        raise


def _windows_close_handle(kernel32: Any, handle: Any) -> None:
    from ctypes import wintypes

    close_handle = kernel32.CloseHandle
    close_handle.argtypes = [wintypes.HANDLE]
    close_handle.restype = wintypes.BOOL
    if not close_handle(handle):
        raise NativePolicySnapshotError("native_policy_windows_handle_close_failed")


def _windows_apply_private_dacl(kernel32: Any, handle: Any, descriptor: Any, dacl: Any, directory: bool) -> None:
    import ctypes
    from ctypes import wintypes

    del kernel32, descriptor, directory
    advapi32 = _snapshot_api()._windows_dll("advapi32")
    setter = advapi32.SetSecurityInfo
    setter.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
    ]
    setter.restype = wintypes.DWORD
    result = int(
        setter(
            handle,
            _WINDOWS_SE_FILE_OBJECT,
            _WINDOWS_SECURITY_INFORMATION,
            None,
            None,
            dacl,
            None,
        )
    )
    if result != 0:
        raise NativePolicySnapshotError("native_policy_windows_acl_apply_failed")
