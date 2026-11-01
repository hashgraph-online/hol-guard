"""Trusted Windows system-path discovery that does not consume ambient variables."""

from __future__ import annotations

import ctypes
import importlib
import ntpath
import os
import time
from collections.abc import Callable
from contextlib import suppress
from ctypes import wintypes
from pathlib import Path
from typing import cast

_WINDOWS_PATH_BUFFER_SIZE = 32_768
_WINDOWS_FILE_ATTRIBUTE_DIRECTORY = 0x00000010
_FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
_WINDOWS_FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
_WINDOWS_FILE_FLAG_SEQUENTIAL_SCAN = 0x08000000
_WINDOWS_GENERIC_READ = 0x80000000
_WINDOWS_FILE_SHARE_READ = 0x00000001
_WINDOWS_OPEN_EXISTING = 3
_WINDOWS_ERROR_SHARING_VIOLATION = 32
_WINDOWS_LOCK_OPEN_ATTEMPTS = 6
_WINDOWS_LOCK_RETRY_SECONDS = 0.01
_LIFECYCLE_FEATURE = "native-windows-process-lifecycle-v1"
_LIFECYCLE_COMMAND = "windows-process-lifecycle"
_LIFECYCLE_SCHEMA = "windows-process-lifecycle.v1"
_LIFECYCLE_OUTPUT_LIMIT = 64 * 1024
_LIFECYCLE_MAX_TIMEOUT_MS = 600_000
_LIFECYCLE_TIMEOUT_SECONDS = 10.0
# What a bounded termination may take beyond its own timeout: starting the
# runtime and reading its answer.
_LIFECYCLE_TERMINATION_GRACE_SECONDS = 1.0
_DIRECTORIES_FEATURE = "native-windows-trusted-directories-v1"
_DIRECTORIES_COMMAND = "windows-trusted-directories"
_DIRECTORIES_SCHEMA = "windows-trusted-directories.v1"
_DIRECTORIES_OUTPUT_LIMIT = 256 * 1024
_DIRECTORIES_TIMEOUT_SECONDS = 10.0


class _WindowsByHandleFileInformation(ctypes.Structure):
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


def open_windows_locked_regular_descriptor(
    path: Path | str,
    *,
    expected_resolved_path: Path | str | None = None,
) -> int:
    """Open one regular file while denying concurrent write/delete access.

    The returned CRT descriptor owns the native handle.  ``FILE_SHARE_READ``
    deliberately excludes write and delete sharing, so the pathname cannot be
    replaced and an existing writer cannot coexist while trusted bytes are
    hashed. An expected canonical path additionally binds the native handle to
    that physical path, including when an ancestor junction changes at open.
    """

    try:
        msvcrt = importlib.import_module("msvcrt")
        handle, close_handle = _open_windows_locked_handle(path, expected_resolved_path=expected_resolved_path)
        try:
            return int(
                msvcrt.open_osfhandle(
                    handle,
                    os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOINHERIT", 0),
                )
            )
        except BaseException:
            _ = close_handle(handle)
            raise
    except (AttributeError, ImportError, RuntimeError, TypeError, ValueError) as exc:
        raise OSError("windows_locked_file_unavailable") from exc


def _open_windows_locked_handle(
    path: Path | str,
    *,
    expected_resolved_path: Path | str | None,
) -> tuple[int, Callable[[int], object]]:
    if os.name != "nt":
        raise OSError("windows_locked_file_unavailable")
    win_dll = getattr(ctypes, "WinDLL", None)
    if win_dll is None:
        raise OSError("windows_locked_file_unavailable")
    handle: object | None = None
    close_handle = None
    try:
        kernel32 = win_dll("kernel32", use_last_error=True)
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
        get_information = kernel32.GetFileInformationByHandle
        get_information.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(_WindowsByHandleFileInformation),
        ]
        get_information.restype = wintypes.BOOL
        close_handle = kernel32.CloseHandle
        close_handle.argtypes = [wintypes.HANDLE]
        close_handle.restype = wintypes.BOOL
        invalid_handle = ctypes.c_void_p(-1).value
        for attempt in range(_WINDOWS_LOCK_OPEN_ATTEMPTS):
            handle = create_file(
                str(path),
                _WINDOWS_GENERIC_READ,
                _WINDOWS_FILE_SHARE_READ,
                None,
                _WINDOWS_OPEN_EXISTING,
                _WINDOWS_FILE_FLAG_OPEN_REPARSE_POINT | _WINDOWS_FILE_FLAG_SEQUENTIAL_SCAN,
                None,
            )
            if handle not in {None, invalid_handle}:
                break
            last_error = ctypes.get_last_error()
            sharing_violation = last_error == _WINDOWS_ERROR_SHARING_VIOLATION
            handle = None
            if not sharing_violation or attempt + 1 == _WINDOWS_LOCK_OPEN_ATTEMPTS:
                raise OSError("windows_locked_file_open_failed")
            time.sleep(_WINDOWS_LOCK_RETRY_SECONDS)
        information = _WindowsByHandleFileInformation()
        if not get_information(handle, ctypes.byref(information)):
            raise OSError("windows_locked_file_inspection_failed")
        attributes = int(information.dwFileAttributes)
        is_directory = bool(attributes & _WINDOWS_FILE_ATTRIBUTE_DIRECTORY)
        if attributes & _FILE_ATTRIBUTE_REPARSE_POINT or is_directory:
            raise OSError("windows_locked_file_not_regular")
        if expected_resolved_path is not None:
            get_final_path = kernel32.GetFinalPathNameByHandleW
            get_final_path.argtypes = [wintypes.HANDLE, wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD]
            get_final_path.restype = wintypes.DWORD
            buffer = ctypes.create_unicode_buffer(_WINDOWS_PATH_BUFFER_SIZE)
            length = int(get_final_path(handle, buffer, len(buffer), 0))
            if length <= 0 or length >= len(buffer):
                raise OSError("windows_locked_file_final_path_unavailable")
            # FILE_NAME_NORMALIZED | VOLUME_NAME_DOS resolves junction targets.
            # Never resolve the expected path here: its pre-open identity is
            # the boundary against which this opened handle must be checked.
            if _canonical_windows_path(buffer.value) != _canonical_windows_path(expected_resolved_path):
                raise OSError("windows_locked_file_path_changed")
        handle_value = handle if isinstance(handle, int) else getattr(handle, "value", None)
        if not isinstance(handle_value, int):
            raise OSError("windows_locked_file_handle_invalid")
        handle = None
        return handle_value, close_handle
    except (AttributeError, ImportError, RuntimeError, TypeError, ValueError) as exc:
        raise OSError("windows_locked_file_unavailable") from exc
    finally:
        if handle is not None and close_handle is not None:
            with suppress(OSError, RuntimeError, TypeError, ValueError):
                _ = close_handle(handle)


def _canonical_windows_path(path: Path | str) -> str:
    value = ntpath.normpath(os.fspath(path))
    if value[:8].upper() == "\\\\?\\UNC\\":
        value = "\\\\" + value[8:]
    elif value.startswith("\\\\?\\"):
        value = value[4:]
    if not ntpath.isabs(value) or not ntpath.splitdrive(value)[0]:
        raise OSError("windows_locked_file_expected_path_not_absolute")
    # Case-sensitive Windows directories can contain distinct names which
    # normcase would conflate. Both operands must already be canonical paths.
    return value


def _lifecycle_answer(
    request: dict[str, object],
    *,
    output_limit: int,
    deadline: float | None = None,
) -> dict[str, object] | None:
    from .mdm.runtime_request import runtime_answer

    return runtime_answer(
        _LIFECYCLE_FEATURE,
        _LIFECYCLE_COMMAND,
        {"schema": _LIFECYCLE_SCHEMA, **request},
        output_limit=output_limit,
        timeout_seconds=_LIFECYCLE_TIMEOUT_SECONDS,
        deadline=deadline,
    )


def _lifecycle_fact(op: str, pid: int, field: str) -> object:
    """The runtime's one answer for `pid`, or ``None`` when it gave none."""

    answer = _lifecycle_answer({"op": op, "pids": [pid]}, output_limit=_LIFECYCLE_OUTPUT_LIMIT)
    values = answer.get(field) if answer is not None else None
    if not isinstance(values, list) or len(cast(list[object], values)) != 1:
        return None
    return cast(list[object], values)[0]


def windows_command_line_to_argv(command: str) -> list[str] | None:
    """Parse one native Windows command line with the operating-system ABI."""

    if os.name != "nt" or not command:
        return None
    answer = _lifecycle_answer(
        {"op": "command_line_to_argv", "command": command},
        output_limit=len(command.encode("utf-8", "surrogatepass")) * 6 + _LIFECYCLE_OUTPUT_LIMIT,
    )
    argv = answer.get("argv") if answer is not None else None
    if not isinstance(argv, list) or not argv:
        return None
    arguments = cast(list[object], argv)
    if not all(isinstance(argument, str) for argument in arguments):
        return None
    return cast(list[str], arguments)


def windows_process_liveness(pid: int) -> bool | None:
    """Return live/dead for a Windows PID, or ``None`` when proof is unavailable."""

    if os.name != "nt" or pid <= 0:
        return False
    liveness = _lifecycle_fact("liveness", pid, "liveness")
    return liveness if isinstance(liveness, bool) else None


def windows_process_is_running(pid: int) -> bool:
    """Fail closed when a Windows PID cannot be proven dead."""

    return windows_process_liveness(pid) is not False


def windows_process_owner_sid(pid: int) -> str | None:
    """Return the OS-owned SID for the token attached to one Windows PID."""

    if os.name != "nt" or pid <= 0:
        return None
    owner_sid = _lifecycle_fact("owner_sid", pid, "owner_sids")
    return owner_sid if isinstance(owner_sid, str) and owner_sid.startswith("sid:") and owner_sid != "sid:" else None


def windows_current_owner_sid() -> str | None:
    """Return the SID this process's token runs as, read by the native runtime.

    The runtime inherits this process's primary token and reads its own, so a
    restricted token that keeps it from opening this process by id still
    answers. A runtime too old for the op is asked for this process by id.
    """

    if os.name != "nt":
        return None
    answer = _lifecycle_answer({"op": "current_owner_sid"}, output_limit=_LIFECYCLE_OUTPUT_LIMIT)
    if answer is None:
        return windows_process_owner_sid(os.getpid())
    owner_sid = answer.get("owner_sid")
    return owner_sid if isinstance(owner_sid, str) and owner_sid.startswith("sid:") and owner_sid != "sid:" else None


def windows_process_creation_time(pid: int) -> int | None:
    """Return the kernel process creation timestamp used to defeat PID reuse."""

    if os.name != "nt" or pid <= 0:
        return None
    creation_time = _lifecycle_fact("creation_time", pid, "creation_times")
    return creation_time if type(creation_time) is int and creation_time > 0 else None


def windows_terminate_process_if_creation_time(
    pid: int,
    expected_creation_time: int,
    *,
    timeout: float | None = None,
) -> bool:
    """Terminate the exact PID generation through the handle used to validate it."""

    if os.name != "nt" or pid <= 0 or expected_creation_time <= 0:
        return False
    request: dict[str, object] = {
        "op": "terminate_if_creation_time",
        "pid": pid,
        "expected_creation_time": expected_creation_time,
    }
    deadline = None
    if timeout is not None:
        timeout_ms = min(_LIFECYCLE_MAX_TIMEOUT_MS, int(max(0.0, timeout) * 1000))
        request["timeout_ms"] = timeout_ms
        # The status check, the spawn and the native wait share the caller's
        # budget.
        deadline = time.monotonic() + timeout_ms / 1000 + _LIFECYCLE_TERMINATION_GRACE_SECONDS
    answer = _lifecycle_answer(request, output_limit=_LIFECYCLE_OUTPUT_LIMIT, deadline=deadline)
    return answer is not None and answer.get("terminated") is True


def _directories_answer(request: dict[str, object]) -> dict[str, object] | None:
    from .mdm.runtime_request import runtime_answer

    return runtime_answer(
        _DIRECTORIES_FEATURE,
        _DIRECTORIES_COMMAND,
        {"schema": _DIRECTORIES_SCHEMA, **request},
        output_limit=_DIRECTORIES_OUTPUT_LIMIT,
        timeout_seconds=_DIRECTORIES_TIMEOUT_SECONDS,
    )


def _trusted_paths(op: str, failure_reason: str, *, count: int, **request: object) -> list[Path]:
    """The real paths the runtime answers for `op`, or `OSError(failure_reason)`."""

    if os.name != "nt":
        raise OSError(failure_reason)
    answer = _directories_answer({"op": op, **request})
    paths = answer.get("paths") if answer is not None else None
    if not isinstance(paths, list) or len(cast(list[object], paths)) != count:
        raise OSError(failure_reason)
    values = cast(list[object], paths)
    if not all(isinstance(value, str) and ntpath.isabs(value) for value in values):
        raise OSError(failure_reason)
    return [Path(cast(str, value)) for value in values]


def trusted_windows_system_directories() -> tuple[Path, Path]:
    """Return kernel-reported Windows and System32 directories."""

    windows_directory, system_directory = _trusted_paths(
        "system_directories", "windows_system_directory_unavailable", count=2
    )
    return windows_directory, system_directory


def trusted_windows_system_executable(*relative_parts: str) -> Path:
    """Return one regular, non-reparse executable below native System32."""

    if not relative_parts or any(not part or ntpath.isabs(part) for part in relative_parts):
        raise OSError("windows_system_executable_untrusted")
    return _trusted_paths(
        "system_executable",
        "windows_system_executable_unavailable",
        count=1,
        relative_parts=list(relative_parts),
    )[0]


def trusted_windows_user_profile() -> Path:
    """Return the current user's profile through the Known Folder API."""

    return _trusted_paths("user_profile", "windows_user_profile_unavailable", count=1)[0]


def trusted_windows_roaming_appdata() -> Path:
    """Return the current user's potentially redirected Roaming AppData path."""

    return _trusted_paths("roaming_appdata", "windows_roaming_appdata_unavailable", count=1)[0]


def trusted_windows_local_temp() -> Path:
    """Return the default Temp directory in the current user's profile.

    TEMP changes between processes, and so does the Local AppData known
    folder, which Windows expands from USERPROFILE. The profile itself comes
    from the registry, so a file one process writes here can be found by
    another with a different environment.
    """

    return _trusted_paths("local_temp", "windows_local_temp_unavailable", count=1)[0]


__all__ = [
    "open_windows_locked_regular_descriptor",
    "trusted_windows_local_temp",
    "trusted_windows_roaming_appdata",
    "trusted_windows_system_directories",
    "trusted_windows_system_executable",
    "trusted_windows_user_profile",
    "windows_command_line_to_argv",
    "windows_process_creation_time",
    "windows_process_is_running",
    "windows_process_liveness",
    "windows_process_owner_sid",
    "windows_terminate_process_if_creation_time",
]
