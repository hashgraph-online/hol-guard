"""Typed bindings for the Windows token APIs used by device-key checks."""

from __future__ import annotations

import ctypes
from collections.abc import Callable
from ctypes import wintypes
from dataclasses import dataclass
from typing import Protocol, cast


class _WindowsFunction(Protocol):
    argtypes: object
    restype: object

    def __call__(self, *args: object) -> object: ...


class _WindowsLibrary(Protocol):
    GetCurrentProcess: _WindowsFunction
    OpenProcessToken: _WindowsFunction
    GetTokenInformation: _WindowsFunction
    ConvertSidToStringSidW: _WindowsFunction
    LocalFree: _WindowsFunction
    CloseHandle: _WindowsFunction


@dataclass(frozen=True, slots=True)
class WindowsTokenApi:
    get_current_process: _WindowsFunction
    open_process_token: _WindowsFunction
    get_token_information: _WindowsFunction
    convert_sid: _WindowsFunction
    local_free: _WindowsFunction
    close_handle: _WindowsFunction


def _configure(function: _WindowsFunction, argtypes: object, restype: object) -> _WindowsFunction:
    function.argtypes = argtypes
    function.restype = restype
    return function


def load_windows_token_api() -> WindowsTokenApi:
    """Load and type the Windows token functions, or fail closed off Windows."""

    win_dll = cast(Callable[..., _WindowsLibrary], getattr(ctypes, "WinDLL", None))
    if not callable(win_dll):
        raise OSError("device_key_system_context_required")
    try:
        advapi32 = win_dll("advapi32", use_last_error=True)
        kernel32 = win_dll("kernel32", use_last_error=True)
    except (OSError, RuntimeError, TypeError, ValueError) as error:
        raise OSError("device_key_system_context_required") from error

    return WindowsTokenApi(
        get_current_process=_configure(kernel32.GetCurrentProcess, [], wintypes.HANDLE),
        open_process_token=_configure(
            advapi32.OpenProcessToken,
            [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)],
            wintypes.BOOL,
        ),
        get_token_information=_configure(
            advapi32.GetTokenInformation,
            [
                wintypes.HANDLE,
                wintypes.DWORD,
                wintypes.LPVOID,
                wintypes.DWORD,
                ctypes.POINTER(wintypes.DWORD),
            ],
            wintypes.BOOL,
        ),
        convert_sid=_configure(
            advapi32.ConvertSidToStringSidW,
            [wintypes.LPVOID, ctypes.POINTER(wintypes.LPWSTR)],
            wintypes.BOOL,
        ),
        local_free=_configure(kernel32.LocalFree, [wintypes.HLOCAL], wintypes.HLOCAL),
        close_handle=_configure(kernel32.CloseHandle, [wintypes.HANDLE], wintypes.BOOL),
    )


__all__ = ["WindowsTokenApi", "load_windows_token_api"]
