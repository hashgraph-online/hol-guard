"""Bounded native Windows process discovery for daemon ownership checks."""

from __future__ import annotations

import ctypes
import ntpath
import os
from contextlib import suppress
from ctypes import wintypes
from typing import Any

from .windows_paths import windows_process_liveness

_WINDOWS_PROCESS_QUERY_LIMITED_INFORMATION = 0x00001000
_WINDOWS_PROCESS_COMMAND_LINE_INFORMATION = 60
_WINDOWS_PROCESS_ENUMERATION_LIMIT = 65_536
_WINDOWS_PROCESS_IMAGE_PATH_CHARS = 32_768
_WINDOWS_PROCESS_COMMAND_LINE_BUFFER_LIMIT_BYTES = 128 * 1024
_WINDOWS_PROCESS_COMMAND_LINE_TOTAL_LIMIT_BYTES = 1024 * 1024


class _WindowsUnicodeString(ctypes.Structure):
    _fields_ = [
        ("length", wintypes.USHORT),
        ("maximum_length", wintypes.USHORT),
        ("buffer", ctypes.c_void_p),
    ]


def native_windows_process_inventory_available() -> bool:
    """Return whether the native process APIs can be loaded on this host."""

    return _load_process_apis() is not None


def _load_process_apis() -> tuple[Any, Any, Any, Any, Any] | None:
    if os.name != "nt":
        return None
    win_dll = getattr(ctypes, "WinDLL", None)
    if win_dll is None:
        return None
    try:
        kernel32 = win_dll("kernel32", use_last_error=True)
        psapi = win_dll("psapi", use_last_error=True)

        enum_processes = psapi.EnumProcesses
        enum_processes.argtypes = [
            ctypes.POINTER(wintypes.DWORD),
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
        ]
        enum_processes.restype = wintypes.BOOL

        open_process = kernel32.OpenProcess
        open_process.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        open_process.restype = wintypes.HANDLE

        query_image = kernel32.QueryFullProcessImageNameW
        query_image.argtypes = [
            wintypes.HANDLE,
            wintypes.DWORD,
            wintypes.LPWSTR,
            ctypes.POINTER(wintypes.DWORD),
        ]
        query_image.restype = wintypes.BOOL

        query_information = win_dll(
            "ntdll",
            use_last_error=True,
        ).NtQueryInformationProcess
        query_information.argtypes = [
            wintypes.HANDLE,
            wintypes.ULONG,
            ctypes.c_void_p,
            wintypes.ULONG,
            ctypes.POINTER(wintypes.ULONG),
        ]
        query_information.restype = wintypes.LONG

        close_handle = kernel32.CloseHandle
        close_handle.argtypes = [wintypes.HANDLE]
        close_handle.restype = wintypes.BOOL
    except (AttributeError, OSError, TypeError, ValueError):
        return None
    return enum_processes, open_process, query_image, query_information, close_handle


def _process_ids(enum_processes: Any, *, max_processes: int) -> list[int] | None:
    process_ids = (wintypes.DWORD * max_processes)()
    bytes_returned = wintypes.DWORD()
    try:
        success = enum_processes(
            process_ids,
            ctypes.sizeof(process_ids),
            ctypes.byref(bytes_returned),
        )
    except (OSError, TypeError, ValueError):
        return None
    process_id_size = ctypes.sizeof(wintypes.DWORD)
    returned = int(bytes_returned.value)
    if not success or returned == 0 or returned % process_id_size != 0 or returned >= ctypes.sizeof(process_ids):
        return None
    return [int(pid) for pid in process_ids[: returned // process_id_size] if int(pid) > 0]


def _process_image_name(process_handle: object, query_image: Any) -> str | None:
    image_buffer = ctypes.create_unicode_buffer(_WINDOWS_PROCESS_IMAGE_PATH_CHARS)
    image_size = wintypes.DWORD(_WINDOWS_PROCESS_IMAGE_PATH_CHARS)
    try:
        if not query_image(
            process_handle,
            0,
            image_buffer,
            ctypes.byref(image_size),
        ):
            return None
    except (OSError, TypeError, ValueError):
        return None
    image = image_buffer.value.strip()
    return ntpath.basename(image).lower() if image else None


def _command_line_from_handle(
    process_handle: object,
    query_information: Any,
    *,
    max_command_line_bytes: int,
) -> str | None:
    if not 0 < max_command_line_bytes <= _WINDOWS_PROCESS_COMMAND_LINE_TOTAL_LIMIT_BYTES:
        return None
    structure_size = ctypes.sizeof(_WindowsUnicodeString)
    query_limit = min(
        _WINDOWS_PROCESS_COMMAND_LINE_BUFFER_LIMIT_BYTES,
        max(structure_size, (max_command_line_bytes * 2) + structure_size + 2),
    )
    required = wintypes.ULONG()
    try:
        _ = query_information(
            process_handle,
            _WINDOWS_PROCESS_COMMAND_LINE_INFORMATION,
            None,
            0,
            ctypes.byref(required),
        )
        required_bytes = int(required.value)
        if not structure_size <= required_bytes <= query_limit:
            return None
        raw_buffer = ctypes.create_string_buffer(required_bytes)
        status = int(
            query_information(
                process_handle,
                _WINDOWS_PROCESS_COMMAND_LINE_INFORMATION,
                raw_buffer,
                required_bytes,
                ctypes.byref(required),
            )
        )
        if status != 0:
            return None
        value = ctypes.cast(
            raw_buffer,
            ctypes.POINTER(_WindowsUnicodeString),
        ).contents
        raw_start = ctypes.addressof(raw_buffer)
        raw_end = raw_start + ctypes.sizeof(raw_buffer)
        buffer_start = int(value.buffer or 0)
        value_length = int(value.length)
        if (
            value_length <= 0
            or value_length % 2 != 0
            or value_length > int(value.maximum_length)
            or buffer_start < raw_start
            or buffer_start + value_length > raw_end
        ):
            return None
        command_line = ctypes.wstring_at(buffer_start, value_length // 2).strip()
        if not command_line:
            return None
        if len(command_line.encode("utf-8", errors="strict")) > max_command_line_bytes:
            return None
        return command_line
    except (OSError, OverflowError, TypeError, UnicodeError, ValueError):
        return None


def windows_process_command_line(
    pid: int,
    *,
    max_command_line_bytes: int = _WINDOWS_PROCESS_COMMAND_LINE_TOTAL_LIMIT_BYTES,
) -> str | None:
    """Read one Windows process command line through bounded native APIs."""

    if pid <= 0 or not 0 < max_command_line_bytes <= _WINDOWS_PROCESS_COMMAND_LINE_TOTAL_LIMIT_BYTES:
        return None
    apis = _load_process_apis()
    if apis is None:
        return None
    _enum_processes, open_process, _query_image, query_information, close_handle = apis
    try:
        process_handle = open_process(
            _WINDOWS_PROCESS_QUERY_LIMITED_INFORMATION,
            False,
            pid,
        )
    except (OSError, TypeError, ValueError):
        return None
    if not process_handle:
        return None
    try:
        return _command_line_from_handle(
            process_handle,
            query_information,
            max_command_line_bytes=max_command_line_bytes,
        )
    finally:
        with suppress(OSError, TypeError, ValueError):
            _ = close_handle(process_handle)


def windows_process_command_line_inventory(
    *,
    candidate_executable_names: frozenset[str],
    max_processes: int = _WINDOWS_PROCESS_ENUMERATION_LIMIT,
    max_command_line_bytes: int = _WINDOWS_PROCESS_COMMAND_LINE_TOTAL_LIMIT_BYTES,
) -> list[tuple[int, str]] | None:
    """Return bounded command lines for candidate Windows process images."""

    if (
        not 0 < max_processes <= _WINDOWS_PROCESS_ENUMERATION_LIMIT
        or not 0 < max_command_line_bytes <= _WINDOWS_PROCESS_COMMAND_LINE_TOTAL_LIMIT_BYTES
    ):
        return None
    candidates = frozenset(
        ntpath.basename(value.strip()).lower()
        for value in candidate_executable_names
        if isinstance(value, str) and value.strip()
    )
    if not candidates:
        return []
    apis = _load_process_apis()
    if apis is None:
        return None
    enum_processes, open_process, query_image, query_information, close_handle = apis
    process_ids = _process_ids(enum_processes, max_processes=max_processes)
    if process_ids is None:
        return None

    entries: list[tuple[int, str]] = []
    consumed_command_line_bytes = 0
    for pid in process_ids:
        try:
            process_handle = open_process(
                _WINDOWS_PROCESS_QUERY_LIMITED_INFORMATION,
                False,
                pid,
            )
        except (OSError, TypeError, ValueError):
            continue
        if not process_handle:
            continue
        try:
            image_name = _process_image_name(process_handle, query_image)
            if image_name not in candidates:
                continue
            remaining_bytes = max_command_line_bytes - consumed_command_line_bytes
            if remaining_bytes <= 0:
                return None
            command_line = _command_line_from_handle(
                process_handle,
                query_information,
                max_command_line_bytes=remaining_bytes,
            )
            if command_line is None:
                if windows_process_liveness(pid) is False:
                    continue
                return None
            if windows_process_liveness(pid) is False:
                continue
            command_line_size = len(command_line.encode("utf-8", errors="strict"))
            if command_line_size > remaining_bytes:
                return None
            consumed_command_line_bytes += command_line_size
            entries.append((pid, command_line))
        finally:
            with suppress(OSError, TypeError, ValueError):
                _ = close_handle(process_handle)
    return sorted(entries, key=lambda item: item[0])


__all__ = [
    "native_windows_process_inventory_available",
    "windows_process_command_line",
    "windows_process_command_line_inventory",
]
