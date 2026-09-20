"""Select one compatible atomic replacement for an owned Windows temporary file."""

from __future__ import annotations

import ctypes
import importlib
import os
import sys
from collections.abc import Callable
from ctypes import wintypes
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import windows_replaceable_file as reader

_DELETE = 0x00010000
_READ_ATTRIBUTES = 0x00000080
_TRAVERSE = 0x00000020
_BACKUP_SEMANTICS = 0x02000000
_FILE_RENAME_INFO_EX = 22
_REPLACE_WITH_POSIX_SEMANTICS = 3
_DIRECTORY = 0x10
_REPARSE_POINT = 0x400
_POSIX_UNLINK_RENAME = 0x00000400
_MINIMUM_EX_VERSION = (10, 0, 14393)


class _RenameInfo(ctypes.Structure):
    # The SDK has one union at offset zero, not a second BOOLEAN field.
    _fields_ = [
        ("Flags", wintypes.DWORD),
        ("RootDirectory", wintypes.HANDLE),
        ("FileNameLength", wintypes.DWORD),
        ("FileName", wintypes.WCHAR * 1),
    ]


@dataclass(frozen=True)
class SourceIdentity:
    volume: int
    index_high: int
    index_low: int
    size_high: int
    size_low: int


def _api() -> Any:
    api = reader._file_api()
    api.SetFileInformationByHandle.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
    ]
    api.SetFileInformationByHandle.restype = wintypes.BOOL
    api.GetHandleInformation.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    api.GetHandleInformation.restype = wintypes.BOOL
    api.GetVolumeInformationByHandleW.argtypes = [
        wintypes.HANDLE,
        wintypes.LPWSTR,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(wintypes.DWORD),
        wintypes.LPWSTR,
        wintypes.DWORD,
    ]
    api.GetVolumeInformationByHandleW.restype = wintypes.BOOL
    return api


def _error(source: str, destination: str) -> OSError:
    # Borrow GetLastError before formatting or any cleanup can overwrite it.
    code = ctypes.get_last_error()
    error = ctypes.WinError(code)
    return OSError(error.errno, error.strerror, source, code, destination)


def _information(api: Any, handle: int, *, directory: bool, source: str, destination: str) -> Any:
    information = reader._WindowsByHandleFileInformation()
    if not api.GetFileInformationByHandle(handle, ctypes.byref(information)):
        raise _error(source, destination)
    attributes = int(information.dwFileAttributes)
    if bool(attributes & _DIRECTORY) != directory or attributes & _REPARSE_POINT:
        raise OSError("windows_private_replace_opened_object_type_invalid")
    reader._require_disk(api, handle)
    inherited = wintypes.DWORD()
    if not api.GetHandleInformation(handle, ctypes.byref(inherited)):
        raise _error(source, destination)
    if inherited.value & 1:
        raise OSError("windows_private_replace_handle_inherited")
    return information


def _identity(information: Any) -> SourceIdentity:
    return SourceIdentity(
        int(information.dwVolumeSerialNumber),
        int(information.nFileIndexHigh),
        int(information.nFileIndexLow),
        int(information.nFileSizeHigh),
        int(information.nFileSizeLow),
    )


def snapshot_descriptor(descriptor: int) -> SourceIdentity:
    """Bind the already flushed original writer handle before its original close."""

    if os.name != "nt":
        raise OSError("windows_private_replace_requires_windows")
    native = int(importlib.import_module("msvcrt").get_osfhandle(descriptor))
    information = _information(_api(), native, directory=False, source="", destination="")
    return _identity(information)


def prepare_replace(descriptor: int, source: Path, destination: Path) -> SourceIdentity | None:
    """Select Ex only from positive OS and exact-handle filesystem admission."""

    if os.name != "nt":
        return None
    version_reader = getattr(sys, "getwindowsversion", None)
    if version_reader is None:
        return None
    try:
        version = version_reader()
    except OSError:
        return None
    if (version.major, version.minor, version.build) < _MINIMUM_EX_VERSION:
        return None
    try:
        names = _names(source, destination)
    except ValueError:
        # Retain the original path conversion and os.replace behavior for path
        # forms outside this private same-directory absolute-name operation.
        return None
    try:
        api = _api()
    except AttributeError:
        return None
    native = int(importlib.import_module("msvcrt").get_osfhandle(descriptor))
    flags = wintypes.DWORD()
    if not api.GetVolumeInformationByHandleW(native, None, 0, None, None, ctypes.byref(flags), None, 0):
        return None
    if not flags.value & _POSIX_UNLINK_RENAME:
        return None
    information = _information(api, native, directory=False, source=names[0], destination=names[1])
    return _identity(information)


def replace_temporary_descriptor(
    descriptor: int,
    source: Path,
    destination: Path,
    *,
    close_descriptor: Callable[[int], object],
    legacy_replace: Callable[[Path, Path], object],
) -> None:
    """Own the flushed descriptor through its one close, then mutate once."""

    expected = None
    failure = None
    try:
        expected = prepare_replace(descriptor, source, destination)
    except BaseException as error:
        failure = error
    try:
        close_descriptor(descriptor)
    except BaseException as error:
        if failure is None:
            failure = error
        else:
            reader._note_cleanup_failure(failure, "windows_private_replace_descriptor_close_failed")
    if failure is not None:
        raise failure
    if expected is None:
        # This is a preselected original operation, never a retry after Ex.
        legacy_replace(source, destination)
    else:
        replace_once(source, destination, expected)


def _names(source: Path, destination: Path) -> tuple[str, str]:
    if os.name != "nt":
        raise OSError("windows_private_replace_requires_windows")
    if not source.is_absolute() or not destination.is_absolute() or source.parent != destination.parent:
        raise ValueError("windows_private_replace_requires_absolute_same_directory_paths")
    if source == destination or not destination.name or ":" in destination.name:
        raise ValueError("windows_private_replace_target_name_invalid")
    names = os.fspath(source), os.fspath(destination)
    for name in names:
        if "\0" in name or len(name.encode("utf-16-le", errors="surrogatepass")) // 2 > 32767:
            raise ValueError("windows_private_replace_path_invalid")
    return names


def _open(api: Any, path: str, access: int, sharing: int, attributes: int, names: tuple[str, str]) -> int:
    handle = api.CreateFileW(path, access, sharing, None, reader._OPEN_EXISTING, attributes, None)
    if handle in (None, ctypes.c_void_p(-1).value):
        raise _error(*names)
    return int(handle)


def _rename_buffer(destination: Path, _parent: int) -> ctypes.Array[ctypes.c_char]:
    encoded = os.fspath(destination).encode("utf-16-le", errors="surrogatepass")
    buffer = ctypes.create_string_buffer(ctypes.sizeof(_RenameInfo) + len(encoded) + 2)
    information = _RenameInfo.from_buffer(buffer)
    information.Flags = _REPLACE_WITH_POSIX_SEMANTICS
    information.RootDirectory = None
    information.FileNameLength = len(encoded)
    ctypes.memmove(ctypes.addressof(buffer) + _RenameInfo.FileName.offset, encoded, len(encoded))
    return buffer


def replace_once(source: Path, destination: Path, expected: SourceIdentity) -> None:
    """Attempt one admitted rename; a failure never selects a second mutation."""

    names = _names(source, destination)
    sys.audit("os.rename", *names, -1, -1)
    api = _api()
    parent = native = None
    failure = None
    try:
        parent = _open(
            api,
            str(source.parent),
            _READ_ATTRIBUTES | _TRAVERSE,
            3,
            _BACKUP_SEMANTICS | reader._OPEN_REPARSE_POINT,
            names,
        )
        parent_info = _information(api, parent, directory=True, source=names[0], destination=names[1])
        native = _open(
            api,
            names[0],
            _DELETE | _READ_ATTRIBUTES,
            reader._SHARE_READ_WRITE_DELETE,
            reader._OPEN_REPARSE_POINT,
            names,
        )
        current = _information(api, native, directory=False, source=names[0], destination=names[1])
        if _identity(current) != expected or int(parent_info.dwVolumeSerialNumber) != expected.volume:
            raise OSError("windows_private_replace_source_identity_changed")
        buffer = _rename_buffer(destination, parent)
        if not api.SetFileInformationByHandle(native, _FILE_RENAME_INFO_EX, buffer, ctypes.sizeof(buffer)):
            raise _error(*names)
    except BaseException as error:
        failure = error
    finally:
        for handle in (native, parent):
            if handle is None:
                continue
            try:
                if not api.CloseHandle(handle):
                    raise _error(*names)
            except BaseException as cleanup_error:
                if failure is None:
                    failure = cleanup_error
                else:
                    reader._note_cleanup_failure(failure, "windows_private_replace_native_handle_close_failed")
    if failure is not None:
        raise failure
