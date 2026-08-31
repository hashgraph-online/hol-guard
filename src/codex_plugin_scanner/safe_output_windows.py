"""Windows no-follow output writes with locked parent directory handles."""

from __future__ import annotations

import ctypes
import os
import secrets
from pathlib import Path

_DELETE = 0x00010000
_FILE_ATTRIBUTE_NORMAL = 0x00000080
_FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
_FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
_FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
_FILE_LIST_DIRECTORY = 0x0001
_FILE_TRAVERSE = 0x0020
_FILE_RENAME_INFO_CLASS = 3
_FILE_SHARE_READ = 0x00000001
_GENERIC_WRITE = 0x40000000
_CREATE_NEW = 1
_OPEN_EXISTING = 3
_ERROR_ALREADY_EXISTS = 183
_INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value


class _FileAttributeTagInfo(ctypes.Structure):
    _fields_ = [("file_attributes", ctypes.c_uint32), ("reparse_tag", ctypes.c_uint32)]


class _FileRenameMode(ctypes.Union):
    _fields_ = [("replace_if_exists", ctypes.c_ubyte), ("flags", ctypes.c_uint32)]  # noqa: RUF012


class _FileRenameInfo(ctypes.Structure):
    _anonymous_ = ("mode",)
    _fields_ = [
        ("mode", _FileRenameMode),
        ("root_directory", ctypes.c_void_p),
        ("file_name_length", ctypes.c_uint32),
        ("file_name", ctypes.c_wchar * 1),
    ]


class _WindowsApi:
    def __init__(self) -> None:
        library = ctypes.WinDLL("kernel32", use_last_error=True)
        library.CloseHandle.argtypes = [ctypes.c_void_p]
        library.CloseHandle.restype = ctypes.c_int
        library.CreateDirectoryW.argtypes = [ctypes.c_wchar_p, ctypes.c_void_p]
        library.CreateDirectoryW.restype = ctypes.c_int
        library.CreateFileW.argtypes = [
            ctypes.c_wchar_p,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_void_p,
        ]
        library.CreateFileW.restype = ctypes.c_void_p
        library.DeleteFileW.argtypes = [ctypes.c_wchar_p]
        library.DeleteFileW.restype = ctypes.c_int
        library.FlushFileBuffers.argtypes = [ctypes.c_void_p]
        library.FlushFileBuffers.restype = ctypes.c_int
        library.GetFileInformationByHandleEx.argtypes = [
            ctypes.c_void_p,
            ctypes.c_int,
            ctypes.c_void_p,
            ctypes.c_uint32,
        ]
        library.GetFileInformationByHandleEx.restype = ctypes.c_int
        library.SetFileInformationByHandle.argtypes = [
            ctypes.c_void_p,
            ctypes.c_int,
            ctypes.c_void_p,
            ctypes.c_uint32,
        ]
        library.SetFileInformationByHandle.restype = ctypes.c_int
        library.WriteFile.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_uint32),
            ctypes.c_void_p,
        ]
        library.WriteFile.restype = ctypes.c_int
        self._library = library

    def close_handle(self, handle: int) -> None:
        self._library.CloseHandle(ctypes.c_void_p(handle))

    def create_directory(self, path: Path) -> bool:
        return bool(self._library.CreateDirectoryW(_extended_path(path), None))

    def create_file(self, path: Path, access: int, sharing: int, creation: int, flags: int) -> int:
        handle = self._library.CreateFileW(
            _extended_path(path),
            access,
            sharing,
            None,
            creation,
            flags,
            None,
        )
        return int(handle) if handle is not None else 0

    def delete_file(self, path: Path) -> None:
        self._library.DeleteFileW(_extended_path(path))

    def flush_file(self, handle: int) -> bool:
        return bool(self._library.FlushFileBuffers(ctypes.c_void_p(handle)))

    def inspect_file(self, handle: int, info: _FileAttributeTagInfo) -> bool:
        return bool(
            self._library.GetFileInformationByHandleEx(
                ctypes.c_void_p(handle),
                9,
                ctypes.byref(info),
                ctypes.sizeof(info),
            )
        )

    def rename_file(self, handle: int, buffer: ctypes.Array[ctypes.c_char]) -> bool:
        return bool(
            self._library.SetFileInformationByHandle(
                ctypes.c_void_p(handle),
                _FILE_RENAME_INFO_CLASS,
                buffer,
                len(buffer),
            )
        )

    def write_file(
        self,
        handle: int,
        buffer: ctypes.Array[ctypes.c_char],
        size: int,
        written: ctypes.c_uint32,
    ) -> bool:
        return bool(
            self._library.WriteFile(
                ctypes.c_void_p(handle),
                buffer,
                size,
                ctypes.byref(written),
                None,
            )
        )


def _raise_windows_error(message: str) -> None:
    error_code = ctypes.get_last_error()
    raise OSError(error_code, f"{message}: {ctypes.FormatError(error_code)}")


def _extended_path(path: Path) -> str:
    value = os.path.abspath(path)
    if value.startswith("\\\\?\\"):
        return value
    if value.startswith("\\\\"):
        return f"\\\\?\\UNC\\{value[2:]}"
    return f"\\\\?\\{value}"


def _open_locked_directory(api: _WindowsApi, path: Path) -> int:
    # Deny write/delete sharing so the locked directory cannot be replaced or turned into a junction.
    handle = api.create_file(
        path,
        _FILE_LIST_DIRECTORY | _FILE_TRAVERSE,
        _FILE_SHARE_READ,
        _OPEN_EXISTING,
        _FILE_FLAG_BACKUP_SEMANTICS | _FILE_FLAG_OPEN_REPARSE_POINT,
    )
    if handle == _INVALID_HANDLE_VALUE:
        _raise_windows_error(f"unable to lock output directory {path}")
    info = _FileAttributeTagInfo()
    if not api.inspect_file(handle, info):
        api.close_handle(handle)
        _raise_windows_error(f"unable to inspect output directory {path}")
    if info.file_attributes & _FILE_ATTRIBUTE_REPARSE_POINT:
        api.close_handle(handle)
        raise OSError(f"refusing reparse-point output directory: {path}")
    return int(handle)


def _create_or_lock_directories(api: _WindowsApi, parent: Path) -> list[int]:
    current = Path(parent.anchor)
    handles = [_open_locked_directory(api, current)]
    try:
        for part in parent.parts[1:]:
            current /= part
            if not api.create_directory(current):
                error_code = ctypes.get_last_error()
                if error_code != _ERROR_ALREADY_EXISTS:
                    _raise_windows_error(f"unable to create output directory {current}")
            handles.append(_open_locked_directory(api, current))
    except BaseException:
        for handle in reversed(handles):
            api.close_handle(handle)
        raise
    return handles


def _write_file(api: _WindowsApi, handle: int, payload: bytes) -> None:
    offset = 0
    while offset < len(payload):
        chunk = payload[offset : offset + 1024 * 1024]
        buffer = ctypes.create_string_buffer(chunk)
        written = ctypes.c_uint32()
        if not api.write_file(handle, buffer, len(chunk), written):
            _raise_windows_error("unable to write output file")
        if written.value == 0:
            raise OSError("unable to make progress writing output file")
        offset += written.value
    if not api.flush_file(handle):
        _raise_windows_error("unable to flush output file")


def _rename_file_handle(api: _WindowsApi, handle: int, target: Path) -> None:
    encoded_name = str(target).encode("utf-16-le")
    file_name_offset = _FileRenameInfo.file_name.offset
    # Windows requires the full FILE_RENAME_INFO structure plus the variable
    # filename payload, even though FileNameLength excludes the placeholder.
    buffer = ctypes.create_string_buffer(ctypes.sizeof(_FileRenameInfo) + len(encoded_name))
    info = ctypes.cast(buffer, ctypes.POINTER(_FileRenameInfo)).contents
    info.replace_if_exists = True
    info.root_directory = None
    info.file_name_length = len(encoded_name)
    ctypes.memmove(ctypes.addressof(buffer) + file_name_offset, encoded_name, len(encoded_name))
    if not api.rename_file(handle, buffer):
        _raise_windows_error("unable to atomically replace output file")


def write_bytes_atomic_no_follow_windows(path: Path, payload: bytes) -> None:
    """Write with every ancestor locked against replacement throughout the final rename."""
    absolute = Path(os.path.abspath(path))
    api = _WindowsApi()
    directory_handles = _create_or_lock_directories(api, absolute.parent)
    temporary = absolute.parent / f".{absolute.name}.{secrets.token_hex(16)}"
    temporary_handle: int | None = None
    renamed = False
    try:
        opened = api.create_file(
            temporary,
            _GENERIC_WRITE | _DELETE,
            0,
            _CREATE_NEW,
            _FILE_ATTRIBUTE_NORMAL | _FILE_FLAG_OPEN_REPARSE_POINT,
        )
        if opened == _INVALID_HANDLE_VALUE:
            _raise_windows_error("unable to create temporary output file")
        temporary_handle = int(opened)
        _write_file(api, temporary_handle, payload)
        _rename_file_handle(api, temporary_handle, absolute)
        renamed = True
    finally:
        if temporary_handle is not None:
            api.close_handle(temporary_handle)
        if temporary_handle is not None and not renamed:
            api.delete_file(temporary)
        for handle in reversed(directory_handles):
            api.close_handle(handle)
