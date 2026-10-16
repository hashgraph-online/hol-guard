"""Find the Codex process that launched a hook on Windows."""

from __future__ import annotations

import ctypes
import os
import sys
from collections.abc import Callable
from pathlib import Path

_TH32CS_SNAPPROCESS = 0x2
_PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
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


def windows_codex_ancestor(is_codex: Callable[[str], bool], max_ancestors: int) -> Path | None:
    """The nearest ancestor whose image is Codex, or ``None``."""

    if sys.platform != "win32":
        return None
    try:
        parents = _parents()
        pid = os.getppid()
        for _ in range(max_ancestors):
            if pid <= 4:
                return None
            path = _image_path(pid)
            if path is not None and is_codex(path.name):
                return path
            pid = parents.get(pid, 0)
    except OSError:
        return None
    return None
