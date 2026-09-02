"""Windows handle primitives for native policy state."""

from __future__ import annotations

from contextlib import suppress
from pathlib import Path
from typing import Any, NamedTuple

from .native_policy_snapshot_constants import (
    _WINDOWS_CREATE_NEW,
    _WINDOWS_DELETE,
    _WINDOWS_ERROR_ALREADY_EXISTS,
    _WINDOWS_ERROR_FILE_EXISTS,
    _WINDOWS_ERROR_FILE_NOT_FOUND,
    _WINDOWS_ERROR_PATH_NOT_FOUND,
    _WINDOWS_FILE_ADD_FILE,
    _WINDOWS_FILE_ATTRIBUTE_DIRECTORY,
    _WINDOWS_FILE_ATTRIBUTE_NORMAL,
    _WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT,
    _WINDOWS_FILE_FLAG_BACKUP_SEMANTICS,
    _WINDOWS_FILE_FLAG_OPEN_REPARSE_POINT,
    _WINDOWS_FILE_FLAG_WRITE_THROUGH,
    _WINDOWS_FILE_READ_ATTRIBUTES,
    _WINDOWS_FILE_SHARE_DELETE,
    _WINDOWS_FILE_SHARE_READ,
    _WINDOWS_FILE_SHARE_WRITE,
    _WINDOWS_FILE_TRAVERSE,
    _WINDOWS_FILE_TYPE_DISK,
    _WINDOWS_GENERIC_READ,
    _WINDOWS_GENERIC_WRITE,
    _WINDOWS_OPEN_EXISTING,
    _WINDOWS_SE_FILE_OBJECT,
    _WINDOWS_SECURITY_INFORMATION,
    _WINDOWS_WRITE_DAC,
    NativePolicySnapshotError,
)
from .native_policy_snapshot_windows_atomic import (
    _windows_delete_file_handle,
    _windows_handle_value,
)


def _snapshot_api() -> Any:
    """Resolve façade hooks lazily, preserving established monkeypatch seams."""

    from . import native_policy_snapshot

    return native_policy_snapshot


class _WindowsOpenFunctions(NamedTuple):
    create_file: Any
    close_handle: Any
    get_information: Any
    get_file_type: Any
    information_type: Any


class _WindowsOpenConfiguration(NamedTuple):
    desired_access: int
    share_mode: int
    security_attributes: Any | None
    disposition: int
    flags: int


def _windows_configure_open_functions(api: Any, kernel32: Any) -> _WindowsOpenFunctions:
    import ctypes
    from ctypes import wintypes

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
    information_type = api._windows_file_information_type()
    get_information = kernel32.GetFileInformationByHandle
    get_information.argtypes = [wintypes.HANDLE, ctypes.POINTER(information_type)]
    get_information.restype = wintypes.BOOL
    get_file_type = kernel32.GetFileType
    get_file_type.argtypes = [wintypes.HANDLE]
    get_file_type.restype = wintypes.DWORD
    return _WindowsOpenFunctions(create_file, close_handle, get_information, get_file_type, information_type)


def _windows_open_configuration(
    api: Any,
    *,
    directory: bool,
    create_new: bool,
    descriptor: Any | None,
    repair: bool,
    lock: bool,
    rename_source: bool,
    add_file: bool,
    share_delete: bool,
    rename_parent: bool,
) -> _WindowsOpenConfiguration:
    import ctypes
    from ctypes import wintypes

    flags = _WINDOWS_FILE_FLAG_OPEN_REPARSE_POINT
    if directory:
        flags |= _WINDOWS_FILE_FLAG_BACKUP_SEMANTICS
        # Barrier directory handles withhold delete sharing so the bound
        # directory cannot be renamed. Rename uses a separate parent handle.
        desired_access = _WINDOWS_GENERIC_READ
        if add_file:
            desired_access |= _WINDOWS_FILE_ADD_FILE | _WINDOWS_FILE_TRAVERSE
        share_mode = _WINDOWS_FILE_SHARE_READ if lock else _WINDOWS_FILE_SHARE_READ | _WINDOWS_FILE_SHARE_WRITE
        if add_file:
            share_mode |= _WINDOWS_FILE_SHARE_WRITE
        if rename_parent:
            desired_access = _WINDOWS_FILE_TRAVERSE | _WINDOWS_FILE_READ_ATTRIBUTES
            share_mode = _WINDOWS_FILE_SHARE_READ | _WINDOWS_FILE_SHARE_WRITE | _WINDOWS_FILE_SHARE_DELETE
    else:
        desired_access = _WINDOWS_GENERIC_READ | (_WINDOWS_GENERIC_WRITE if create_new or repair else 0)
        if create_new or rename_source:
            desired_access |= _WINDOWS_DELETE
        share_mode = _WINDOWS_FILE_SHARE_READ
        if share_delete:
            share_mode |= _WINDOWS_FILE_SHARE_DELETE
    if not rename_parent and (descriptor is not None or repair):
        # Existing objects are repaired only after an owner-only check. A
        # creation descriptor is carried by SECURITY_ATTRIBUTES and never
        # requires owner-write or owner-information access.
        desired_access |= _WINDOWS_WRITE_DAC
    if create_new:
        flags |= _WINDOWS_FILE_FLAG_WRITE_THROUGH
        disposition = _WINDOWS_CREATE_NEW
    else:
        disposition = _WINDOWS_OPEN_EXISTING
    security_attributes = None
    if descriptor is not None and create_new:
        security_attributes_type = api._windows_security_attributes_type()
        security_attributes = security_attributes_type(
            ctypes.sizeof(security_attributes_type), descriptor, wintypes.BOOL(False)
        )
    return _WindowsOpenConfiguration(
        desired_access,
        share_mode,
        security_attributes,
        disposition,
        _WINDOWS_FILE_ATTRIBUTE_NORMAL | flags,
    )


def _windows_raise_open_error(path: Path, *, create_new: bool) -> None:
    import ctypes

    error_code = ctypes.get_last_error()
    if error_code in {_WINDOWS_ERROR_FILE_NOT_FOUND, _WINDOWS_ERROR_PATH_NOT_FOUND}:
        raise FileNotFoundError(str(path))
    if create_new and error_code in {_WINDOWS_ERROR_FILE_EXISTS, _WINDOWS_ERROR_ALREADY_EXISTS}:
        raise FileExistsError(str(path))
    raise NativePolicySnapshotError("native_policy_windows_path_open_failed")


def _windows_validate_open_handle(
    *,
    kernel32: Any,
    handle: Any,
    directory: bool,
    functions: _WindowsOpenFunctions,
) -> tuple[Any, Any, Any]:
    import ctypes

    information = functions.information_type()
    if not functions.get_information(handle, ctypes.byref(information)):
        raise NativePolicySnapshotError("native_policy_windows_path_stat_failed")
    file_attributes = int(information.dwFileAttributes)
    expected_directory = bool(file_attributes & _WINDOWS_FILE_ATTRIBUTE_DIRECTORY)
    if (
        bool(directory) != expected_directory
        or file_attributes & _WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT
        or functions.get_file_type(handle) != _WINDOWS_FILE_TYPE_DISK
    ):
        raise NativePolicySnapshotError("native_policy_windows_path_invalid")
    return kernel32, handle, information


def _windows_cleanup_open_handle_failure(
    kernel32: Any,
    handle: Any,
    close_handle: Any,
    *,
    create_new: bool,
) -> None:
    if create_new:
        # A CREATE_NEW handle owns the only newly-created object. Delete it
        # through that handle before closing so failed validation cannot leave
        # a partial or reparse object at the requested path.
        with suppress(BaseException):
            _windows_delete_file_handle(kernel32, handle)
    close_handle(handle)


def _windows_open_handle(
    path: Path,
    *,
    directory: bool,
    create_new: bool = False,
    descriptor: Any | None = None,
    repair: bool = False,
    lock: bool = False,
    rename_source: bool = False,
    add_file: bool = False,
    share_delete: bool = False,
    rename_parent: bool = False,
) -> tuple[Any, Any, Any]:
    """Open/create one non-reparse Windows object while denying deletion."""

    import ctypes

    api = _snapshot_api()
    kernel32 = api._windows_dll("kernel32")
    functions = _windows_configure_open_functions(api, kernel32)
    configuration = _windows_open_configuration(
        api,
        directory=directory,
        create_new=create_new,
        descriptor=descriptor,
        repair=repair,
        lock=lock,
        rename_source=rename_source,
        add_file=add_file,
        share_delete=share_delete,
        rename_parent=rename_parent,
    )
    handle = functions.create_file(
        str(path),
        configuration.desired_access,
        configuration.share_mode,
        ctypes.byref(configuration.security_attributes) if configuration.security_attributes is not None else None,
        configuration.disposition,
        configuration.flags,
        None,
    )
    invalid_handle = ctypes.c_void_p(-1).value
    handle_value = getattr(handle, "value", handle)
    if handle is None or handle_value == invalid_handle:
        _windows_raise_open_error(path, create_new=create_new)
    try:
        return _windows_validate_open_handle(
            kernel32=kernel32,
            handle=handle,
            directory=directory,
            functions=functions,
        )
    except BaseException:
        _windows_cleanup_open_handle_failure(kernel32, handle, functions.close_handle, create_new=create_new)
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


def _windows_write_private_bytes(path: Path, payload: bytes, *, maximum_bytes: int) -> None:
    """Create, verify, and durably write bytes through one private handle."""

    import ctypes
    from ctypes import wintypes

    if not payload or len(payload) > maximum_bytes:
        raise NativePolicySnapshotError("native_policy_windows_write_too_large")
    api = _snapshot_api()
    with api._windows_private_descriptor(False) as (_advapi32, descriptor, _dacl, owner_sid):
        kernel32, handle, _information = api._windows_open_handle(
            path,
            directory=False,
            create_new=True,
            descriptor=descriptor,
        )
        try:
            api._windows_verify_private_dacl(handle, owner_sid=owner_sid, directory=False)
            write_file = kernel32.WriteFile
            write_file.argtypes = [
                wintypes.HANDLE,
                ctypes.c_void_p,
                wintypes.DWORD,
                ctypes.POINTER(wintypes.DWORD),
                ctypes.c_void_p,
            ]
            write_file.restype = wintypes.BOOL
            buffer = (ctypes.c_ubyte * len(payload)).from_buffer_copy(payload)
            written = 0
            while written < len(payload):
                request_size = min(64 * 1024, len(payload) - written)
                count = wintypes.DWORD()
                if not write_file(
                    handle,
                    ctypes.byref(buffer, written),
                    request_size,
                    ctypes.byref(count),
                    None,
                ):
                    raise NativePolicySnapshotError("native_policy_windows_write_failed")
                chunk_size = int(count.value)
                if chunk_size <= 0 or chunk_size > request_size:
                    raise NativePolicySnapshotError("native_policy_windows_write_failed")
                written += chunk_size
            flush = kernel32.FlushFileBuffers
            flush.argtypes = [wintypes.HANDLE]
            flush.restype = wintypes.BOOL
            if not flush(handle):
                raise NativePolicySnapshotError("native_policy_windows_sync_failed")
        finally:
            api._windows_close_handle(kernel32, handle)


def _windows_repair_private_file(path: Path) -> None:
    """Repair a current-owner file DACL through the opened object handle."""

    api = _snapshot_api()
    with api._windows_private_descriptor(False) as (_advapi32, descriptor, dacl, owner_sid):
        kernel32, handle, _information = api._windows_open_handle(
            path,
            directory=False,
            repair=True,
        )
        try:
            api._windows_verify_private_owner(handle, owner_sid=owner_sid)
            api._windows_apply_private_dacl(kernel32, handle, descriptor, dacl, False)
            api._windows_verify_private_dacl(handle, owner_sid=owner_sid, directory=False)
        finally:
            api._windows_close_handle(kernel32, handle)


def _windows_verify_private_file(path: Path) -> None:
    """Verify a committed file through a handle opened without path trust."""

    api = _snapshot_api()
    kernel32, handle, _information = api._windows_open_handle(path, directory=False)
    try:
        owner_sid = api._windows_owner_sid()
        api._windows_verify_private_dacl(handle, owner_sid=owner_sid, directory=False)
    finally:
        api._windows_close_handle(kernel32, handle)


def _windows_open_private_fd(path: Path, *, maximum_bytes: int) -> int:
    """Open/create a private regular file and transfer its handle to CRT fd."""

    import msvcrt
    import os

    api = _snapshot_api()
    if api._windows_path_has_reparse_component(path):
        raise NativePolicySnapshotError("native_policy_windows_path_invalid")
    try:
        with api._windows_private_descriptor(False) as (
            _advapi32,
            descriptor,
            _dacl,
            owner_sid,
        ):
            kernel32, handle, information = api._windows_open_handle(
                path,
                directory=False,
                create_new=True,
                descriptor=descriptor,
            )
            transferred = False
            try:
                size = (int(information.nFileSizeHigh) << 32) | int(information.nFileSizeLow)
                if size > maximum_bytes:
                    raise NativePolicySnapshotError("native_policy_windows_path_invalid")
                api._windows_verify_private_dacl(handle, owner_sid=owner_sid, directory=False)
                descriptor_fd = msvcrt.open_osfhandle(
                    _windows_handle_value(handle),
                    os.O_RDWR | getattr(os, "O_BINARY", 0),
                )
                transferred = True
                return descriptor_fd
            finally:
                if not transferred:
                    api._windows_close_handle(kernel32, handle)
    except FileExistsError:
        pass

    with api._windows_private_descriptor(False) as (_advapi32, descriptor, dacl, owner_sid):
        kernel32, handle, information = api._windows_open_handle(
            path,
            directory=False,
            repair=True,
        )
        transferred = False
        try:
            size = (int(information.nFileSizeHigh) << 32) | int(information.nFileSizeLow)
            if size > maximum_bytes:
                raise NativePolicySnapshotError("native_policy_windows_path_invalid")
            api._windows_verify_private_owner(handle, owner_sid=owner_sid)
            api._windows_apply_private_dacl(kernel32, handle, descriptor, dacl, False)
            api._windows_verify_private_dacl(handle, owner_sid=owner_sid, directory=False)
            descriptor_fd = msvcrt.open_osfhandle(
                _windows_handle_value(handle),
                os.O_RDWR | getattr(os, "O_BINARY", 0),
            )
            transferred = True
            return descriptor_fd
        finally:
            if not transferred:
                api._windows_close_handle(kernel32, handle)
