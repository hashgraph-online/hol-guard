"""Find the Codex process that launched a hook on Windows."""

from __future__ import annotations

import ctypes
import os
import sys
from collections.abc import Callable
from pathlib import Path

_TH32CS_SNAPPROCESS = 0x2
_PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
_SYNCHRONIZE = 0x0010_0000
_WAIT_TIMEOUT = 0x102
_INVALID_HANDLE = ctypes.c_void_p(-1).value
_MAX_PATH_CHARS = 32_768


class _ProcessEntry(ctypes.Structure):
    _fields_ = (
        ("dwSize", ctypes.c_uint32),
        ("cntUsage", ctypes.c_uint32),
        ("th32ProcessID", ctypes.c_uint32),
        ("th32DefaultHeapID", ctypes.c_size_t),
        ("th32ModuleID", ctypes.c_uint32),
        ("cntThreads", ctypes.c_uint32),
        ("th32ParentProcessID", ctypes.c_uint32),
        ("pcPriClassBase", ctypes.c_int32),
        ("dwFlags", ctypes.c_uint32),
        ("szExeFile", ctypes.c_wchar * 260),
    )


def _parents() -> dict[int, int]:
    """Every running process id with its parent, from one snapshot."""

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)  # type: ignore[attr-defined]
    kernel32.CreateToolhelp32Snapshot.restype = ctypes.c_void_p
    snapshot = kernel32.CreateToolhelp32Snapshot(_TH32CS_SNAPPROCESS, 0)
    if snapshot in (None, _INVALID_HANDLE):
        return {}
    parents: dict[int, int] = {}
    try:
        entry = _ProcessEntry()
        entry.dwSize = ctypes.sizeof(entry)
        more = kernel32.Process32FirstW(ctypes.c_void_p(snapshot), ctypes.byref(entry))
        while more:
            parents[entry.th32ProcessID] = entry.th32ParentProcessID
            more = kernel32.Process32NextW(ctypes.c_void_p(snapshot), ctypes.byref(entry))
    finally:
        kernel32.CloseHandle(ctypes.c_void_p(snapshot))
    return parents


def _image_path(pid: int) -> Path | None:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)  # type: ignore[attr-defined]
    kernel32.OpenProcess.restype = ctypes.c_void_p
    handle = kernel32.OpenProcess(_PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not handle:
        return None
    try:
        size = ctypes.c_uint32(_MAX_PATH_CHARS)
        buffer = ctypes.create_unicode_buffer(_MAX_PATH_CHARS)
        if not kernel32.QueryFullProcessImageNameW(ctypes.c_void_p(handle), 0, buffer, ctypes.byref(size)):
            return None
        return Path(buffer.value)
    finally:
        kernel32.CloseHandle(ctypes.c_void_p(handle))


def _start_time(pid: int) -> int | None:
    """A running process's creation time as a FILETIME count, or ``None``
    once it has exited, as ``running_process_start_marker`` answers."""

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)  # type: ignore[attr-defined]
    kernel32.OpenProcess.restype = ctypes.c_void_p
    handle = kernel32.OpenProcess(_SYNCHRONIZE | _PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not handle:
        return None
    try:
        if kernel32.WaitForSingleObject(ctypes.c_void_p(handle), 0) != _WAIT_TIMEOUT:
            return None
        times = [ctypes.c_uint64() for _ in range(4)]
        if not kernel32.GetProcessTimes(ctypes.c_void_p(handle), *(ctypes.byref(time) for time in times)):
            return None
        return times[0].value
    finally:
        kernel32.CloseHandle(ctypes.c_void_p(handle))


def windows_codex_ancestor(is_codex: Callable[[str], bool], max_ancestors: int) -> Path | None:
    """The nearest ancestor whose image is Codex, or ``None``."""

    if sys.platform != "win32":
        return None
    try:
        parents = _parents()
        child = os.getpid()
        child_start = _start_time(child)
        if child_start is None:
            return None
        for _ in range(max_ancestors):
            pid = parents.get(child, 0)
            if pid <= 4:
                return None
            # A parent id outlives its process and can be reused: a parent
            # that started after its child, or whose start cannot be read,
            # is not this hook's ancestor.
            start = _start_time(pid)
            if start is None or start > child_start:
                return None
            path = _image_path(pid)
            if path is not None and is_codex(path.name):
                return path
            child, child_start = pid, start
    except OSError:
        return None
    return None
