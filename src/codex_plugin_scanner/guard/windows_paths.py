"""Trusted Windows system-path discovery that does not consume ambient variables."""

from __future__ import annotations

import ctypes
import ntpath
import os
import stat
import uuid
from contextlib import suppress
from ctypes import wintypes
from pathlib import Path

_WINDOWS_PATH_BUFFER_SIZE = 32_768
_FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
_WINDOWS_ERROR_INVALID_PARAMETER = 87
_WINDOWS_PROCESS_QUERY_LIMITED_INFORMATION = 0x00001000
_WINDOWS_PROCESS_TERMINATE = 0x00000001
_WINDOWS_SYNCHRONIZE = 0x00100000
_WINDOWS_WAIT_OBJECT_0 = 0x00000000
_WINDOWS_WAIT_TIMEOUT = 0x00000102
_WINDOWS_WAIT_FAILED = 0xFFFFFFFF
_FOLDERID_PROFILE = uuid.UUID("5e6c858f-0e22-4760-9afe-ea3317b67173").bytes_le
_FOLDERID_ROAMING_APPDATA = uuid.UUID("3eb685db-65f9-4cf6-a03a-e3ef65729f3d").bytes_le


class _Guid(ctypes.Structure):
    _fields_ = [("bytes", ctypes.c_ubyte * 16)]


def windows_command_line_to_argv(command: str) -> list[str] | None:
    """Parse one native Windows command line with the operating-system ABI."""

    if os.name != "nt" or not command:
        return None
    win_dll = getattr(ctypes, "WinDLL", None)
    if win_dll is None:
        return None
    try:
        shell32 = win_dll("shell32", use_last_error=True)
        kernel32 = win_dll("kernel32", use_last_error=True)
        argument_count = ctypes.c_int()
        command_line_to_argv = shell32.CommandLineToArgvW
        command_line_to_argv.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_int)]
        command_line_to_argv.restype = ctypes.POINTER(wintypes.LPWSTR)
        local_free = kernel32.LocalFree
        local_free.argtypes = [ctypes.c_void_p]
        local_free.restype = ctypes.c_void_p
        arguments = command_line_to_argv(command, ctypes.byref(argument_count))
    except (AttributeError, OSError, TypeError, ValueError):
        return None
    if not arguments or argument_count.value <= 0:
        return None
    try:
        return [str(arguments[index]) for index in range(argument_count.value)]
    except (OSError, TypeError, ValueError):
        return None
    finally:
        with suppress(OSError, TypeError, ValueError):
            _ = local_free(ctypes.cast(arguments, ctypes.c_void_p))


def windows_process_liveness(pid: int) -> bool | None:
    """Return live/dead for a Windows PID, or ``None`` when proof is unavailable."""

    if os.name != "nt" or pid <= 0:
        return False
    win_dll = getattr(ctypes, "WinDLL", None)
    if win_dll is None:
        return None
    try:
        kernel32 = win_dll("kernel32", use_last_error=True)
        open_process = kernel32.OpenProcess
        open_process.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        open_process.restype = wintypes.HANDLE
        wait_for_process = kernel32.WaitForSingleObject
        wait_for_process.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        wait_for_process.restype = wintypes.DWORD
        close_handle = kernel32.CloseHandle
        close_handle.argtypes = [wintypes.HANDLE]
        close_handle.restype = wintypes.BOOL
        process_handle = open_process(_WINDOWS_SYNCHRONIZE, False, pid)
    except (AttributeError, OSError, TypeError, ValueError):
        return None
    if not process_handle:
        if ctypes.get_last_error() == _WINDOWS_ERROR_INVALID_PARAMETER:
            return False
        return None
    try:
        wait_result = int(wait_for_process(process_handle, 0))
    except (OSError, TypeError, ValueError):
        return None
    finally:
        with suppress(OSError, TypeError, ValueError):
            _ = close_handle(process_handle)
    if wait_result == _WINDOWS_WAIT_TIMEOUT:
        return True
    if wait_result == _WINDOWS_WAIT_OBJECT_0:
        return False
    if wait_result == _WINDOWS_WAIT_FAILED:
        return None
    return None


def windows_process_is_running(pid: int) -> bool:
    """Fail closed when a Windows PID cannot be proven dead."""

    return windows_process_liveness(pid) is not False


def windows_process_creation_time(pid: int) -> int | None:
    """Return the kernel process creation timestamp used to defeat PID reuse."""

    if os.name != "nt" or pid <= 0:
        return None
    win_dll = getattr(ctypes, "WinDLL", None)
    if win_dll is None:
        return None
    try:
        kernel32 = win_dll("kernel32", use_last_error=True)
        open_process = kernel32.OpenProcess
        open_process.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        open_process.restype = wintypes.HANDLE
        get_process_times = kernel32.GetProcessTimes
        get_process_times.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(wintypes.FILETIME),
            ctypes.POINTER(wintypes.FILETIME),
            ctypes.POINTER(wintypes.FILETIME),
            ctypes.POINTER(wintypes.FILETIME),
        ]
        get_process_times.restype = wintypes.BOOL
        close_handle = kernel32.CloseHandle
        close_handle.argtypes = [wintypes.HANDLE]
        close_handle.restype = wintypes.BOOL
        process_handle = open_process(_WINDOWS_PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    except (AttributeError, OSError, TypeError, ValueError):
        return None
    if process_handle is None:
        return None
    creation = wintypes.FILETIME()
    exit_time = wintypes.FILETIME()
    kernel_time = wintypes.FILETIME()
    user_time = wintypes.FILETIME()
    try:
        if not get_process_times(
            process_handle,
            ctypes.byref(creation),
            ctypes.byref(exit_time),
            ctypes.byref(kernel_time),
            ctypes.byref(user_time),
        ):
            return None
        return (int(creation.dwHighDateTime) << 32) | int(creation.dwLowDateTime)
    except (OSError, TypeError, ValueError):
        return None
    finally:
        with suppress(OSError, TypeError, ValueError):
            _ = close_handle(process_handle)


def windows_terminate_process_if_creation_time(pid: int, expected_creation_time: int) -> bool:
    """Terminate the exact PID generation through the handle used to validate it."""

    if os.name != "nt" or pid <= 0 or expected_creation_time <= 0:
        return False
    win_dll = getattr(ctypes, "WinDLL", None)
    if win_dll is None:
        return False
    try:
        kernel32 = win_dll("kernel32", use_last_error=True)
        open_process = kernel32.OpenProcess
        open_process.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        open_process.restype = wintypes.HANDLE
        get_process_times = kernel32.GetProcessTimes
        get_process_times.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(wintypes.FILETIME),
            ctypes.POINTER(wintypes.FILETIME),
            ctypes.POINTER(wintypes.FILETIME),
            ctypes.POINTER(wintypes.FILETIME),
        ]
        get_process_times.restype = wintypes.BOOL
        terminate_process = kernel32.TerminateProcess
        terminate_process.argtypes = [wintypes.HANDLE, wintypes.UINT]
        terminate_process.restype = wintypes.BOOL
        wait_for_process = kernel32.WaitForSingleObject
        wait_for_process.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        wait_for_process.restype = wintypes.DWORD
        close_handle = kernel32.CloseHandle
        close_handle.argtypes = [wintypes.HANDLE]
        close_handle.restype = wintypes.BOOL
        process_handle = open_process(
            _WINDOWS_PROCESS_QUERY_LIMITED_INFORMATION | _WINDOWS_PROCESS_TERMINATE | _WINDOWS_SYNCHRONIZE,
            False,
            pid,
        )
    except (AttributeError, OSError, TypeError, ValueError):
        return False
    if process_handle is None:
        return False
    creation = wintypes.FILETIME()
    exit_time = wintypes.FILETIME()
    kernel_time = wintypes.FILETIME()
    user_time = wintypes.FILETIME()
    try:
        if not get_process_times(
            process_handle,
            ctypes.byref(creation),
            ctypes.byref(exit_time),
            ctypes.byref(kernel_time),
            ctypes.byref(user_time),
        ):
            return False
        creation_time = (int(creation.dwHighDateTime) << 32) | int(creation.dwLowDateTime)
        if creation_time != expected_creation_time:
            return False
        wait_result = int(wait_for_process(process_handle, 0))
        if wait_result == _WINDOWS_WAIT_OBJECT_0:
            return True
        if wait_result != _WINDOWS_WAIT_TIMEOUT or not terminate_process(process_handle, 1):
            return False
        return int(wait_for_process(process_handle, 1000)) == _WINDOWS_WAIT_OBJECT_0
    except (OSError, TypeError, ValueError):
        return False
    finally:
        with suppress(OSError, TypeError, ValueError):
            _ = close_handle(process_handle)


def trusted_windows_system_directories() -> tuple[Path, Path]:
    """Return kernel-reported Windows and System32 directories."""

    if os.name != "nt":
        raise OSError("windows_system_directory_unavailable")
    windows_directory = _kernel_directory("GetSystemWindowsDirectoryW")
    system_directory = _kernel_directory("GetSystemDirectoryW")
    if (
        not ntpath.isabs(windows_directory)
        or not ntpath.isabs(system_directory)
        or ntpath.basename(system_directory).lower() != "system32"
        or ntpath.normcase(ntpath.dirname(system_directory)) != ntpath.normcase(windows_directory)
    ):
        raise OSError("windows_system_directory_untrusted")
    windows_path = _trusted_real_directory(Path(windows_directory))
    system_path = _trusted_real_directory(Path(system_directory))
    if ntpath.normcase(str(system_path.parent)) != ntpath.normcase(str(windows_path)):
        raise OSError("windows_system_directory_untrusted")
    return windows_path, system_path


def trusted_windows_system_executable(*relative_parts: str) -> Path:
    """Return one regular, non-reparse executable below native System32."""

    if not relative_parts or any(not part or ntpath.isabs(part) for part in relative_parts):
        raise OSError("windows_system_executable_untrusted")
    _windows_directory, system_directory = trusted_windows_system_directories()
    candidate = system_directory.joinpath(*relative_parts)
    try:
        metadata = candidate.lstat()
    except OSError as error:
        raise OSError("windows_system_executable_unavailable") from error
    attributes = int(getattr(metadata, "st_file_attributes", 0))
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or attributes & _FILE_ATTRIBUTE_REPARSE_POINT
    ):
        raise OSError("windows_system_executable_untrusted")
    resolved = candidate.resolve(strict=True)
    try:
        resolved.relative_to(system_directory)
    except ValueError as error:
        raise OSError("windows_system_executable_untrusted") from error
    return resolved


def trusted_windows_user_profile() -> Path:
    """Return the current user's profile through the Known Folder API."""

    return _trusted_windows_known_folder(
        _FOLDERID_PROFILE,
        failure_reason="windows_user_profile_unavailable",
    )


def trusted_windows_roaming_appdata() -> Path:
    """Return the current user's potentially redirected Roaming AppData path."""

    return _trusted_windows_known_folder(
        _FOLDERID_ROAMING_APPDATA,
        failure_reason="windows_roaming_appdata_unavailable",
    )


def _trusted_windows_known_folder(folder_id_bytes: bytes, *, failure_reason: str) -> Path:
    if os.name != "nt":
        raise OSError(failure_reason)

    folder_id = _Guid((ctypes.c_ubyte * 16).from_buffer_copy(folder_id_bytes))
    folder_pointer = ctypes.c_wchar_p()
    try:
        shell32 = ctypes.windll.shell32
        ole32 = ctypes.windll.ole32
        get_known_folder = shell32.SHGetKnownFolderPath
        get_known_folder.argtypes = [
            ctypes.POINTER(_Guid),
            ctypes.c_ulong,
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_wchar_p),
        ]
        get_known_folder.restype = ctypes.c_long
        free_memory = ole32.CoTaskMemFree
        free_memory.argtypes = [ctypes.c_void_p]
        free_memory.restype = None
        result = int(get_known_folder(ctypes.byref(folder_id), 0, None, ctypes.byref(folder_pointer)))
        if result != 0 or not folder_pointer.value:
            raise OSError(failure_reason)
        return _trusted_real_directory(Path(folder_pointer.value))
    except (AttributeError, OSError, TypeError, ValueError) as error:
        raise OSError(failure_reason) from error
    finally:
        if folder_pointer:
            with suppress(AttributeError, OSError, TypeError, ValueError):
                ctypes.windll.ole32.CoTaskMemFree(ctypes.cast(folder_pointer, ctypes.c_void_p))


def _kernel_directory(function_name: str) -> str:
    buffer = ctypes.create_unicode_buffer(_WINDOWS_PATH_BUFFER_SIZE)
    try:
        function = getattr(ctypes.windll.kernel32, function_name)
        length = int(function(buffer, len(buffer)))
    except (AttributeError, OSError, TypeError, ValueError) as error:
        raise OSError("windows_system_directory_unavailable") from error
    if length <= 0 or length >= len(buffer):
        raise OSError("windows_system_directory_unavailable")
    return ntpath.normpath(str(buffer.value))


def _trusted_real_directory(path: Path) -> Path:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise OSError("windows_system_directory_unavailable") from error
    attributes = int(getattr(metadata, "st_file_attributes", 0))
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or attributes & _FILE_ATTRIBUTE_REPARSE_POINT
    ):
        raise OSError("windows_system_directory_untrusted")
    return path.resolve(strict=True)


__all__ = [
    "trusted_windows_roaming_appdata",
    "trusted_windows_system_directories",
    "trusted_windows_system_executable",
    "trusted_windows_user_profile",
    "windows_command_line_to_argv",
    "windows_process_creation_time",
    "windows_process_is_running",
    "windows_process_liveness",
    "windows_terminate_process_if_creation_time",
]
