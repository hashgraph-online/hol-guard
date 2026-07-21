"""Windows Job Object process-tree boundary for isolated Codex hooks."""

from __future__ import annotations

import contextlib
import ctypes
import subprocess
from ctypes import wintypes
from dataclasses import dataclass
from pathlib import Path

_CREATE_SUSPENDED = 0x00000004
_JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
_JOB_OBJECT_EXTENDED_LIMIT_INFORMATION_CLASS = 9
_TH32CS_SNAPTHREAD = 0x00000004
_THREAD_SUSPEND_RESUME = 0x0002
_RESUME_THREAD_FAILED = 0xFFFFFFFF
_ERROR_NO_MORE_FILES = 18


class _BasicLimitInformation(ctypes.Structure):
    _fields_ = [
        ("per_process_user_time_limit", ctypes.c_longlong),
        ("per_job_user_time_limit", ctypes.c_longlong),
        ("limit_flags", wintypes.DWORD),
        ("minimum_working_set_size", ctypes.c_size_t),
        ("maximum_working_set_size", ctypes.c_size_t),
        ("active_process_limit", wintypes.DWORD),
        ("affinity", ctypes.c_size_t),
        ("priority_class", wintypes.DWORD),
        ("scheduling_class", wintypes.DWORD),
    ]


class _IoCounters(ctypes.Structure):
    _fields_ = [
        ("read_operation_count", ctypes.c_ulonglong),
        ("write_operation_count", ctypes.c_ulonglong),
        ("other_operation_count", ctypes.c_ulonglong),
        ("read_transfer_count", ctypes.c_ulonglong),
        ("write_transfer_count", ctypes.c_ulonglong),
        ("other_transfer_count", ctypes.c_ulonglong),
    ]


class _ExtendedLimitInformation(ctypes.Structure):
    _fields_ = [
        ("basic_limit_information", _BasicLimitInformation),
        ("io_info", _IoCounters),
        ("process_memory_limit", ctypes.c_size_t),
        ("job_memory_limit", ctypes.c_size_t),
        ("peak_process_memory_used", ctypes.c_size_t),
        ("peak_job_memory_used", ctypes.c_size_t),
    ]


class _ThreadEntry32(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ThreadID", wintypes.DWORD),
        ("th32OwnerProcessID", wintypes.DWORD),
        ("tpBasePri", wintypes.LONG),
        ("tpDeltaPri", wintypes.LONG),
        ("dwFlags", wintypes.DWORD),
    ]


@dataclass(slots=True)
class WindowsHookJob:
    """One kill-on-close Windows Job Object handle."""

    handle: int
    closed: bool = False

    def terminate(self) -> None:
        if self.closed:
            return
        kernel32 = _kernel32()
        terminate_job = kernel32.TerminateJobObject
        terminate_job.argtypes = [wintypes.HANDLE, wintypes.UINT]
        terminate_job.restype = wintypes.BOOL
        if not terminate_job(wintypes.HANDLE(self.handle), 1):
            raise OSError(ctypes.get_last_error(), "TerminateJobObject failed")

    def close(self) -> None:
        if self.closed:
            return
        kernel32 = _kernel32()
        close_handle = kernel32.CloseHandle
        close_handle.argtypes = [wintypes.HANDLE]
        close_handle.restype = wintypes.BOOL
        if not close_handle(wintypes.HANDLE(self.handle)):
            raise OSError(ctypes.get_last_error(), "CloseHandle failed")
        self.closed = True


def spawn_windows_hook_process(
    command: list[str],
    *,
    cwd: Path,
    environment: dict[str, str],
) -> tuple[subprocess.Popen[bytes], WindowsHookJob]:
    """Start suspended, assign to a kill-on-close job, then resume."""

    job = _create_job()
    process: subprocess.Popen[bytes] | None = None
    try:
        process = subprocess.Popen(
            command,
            cwd=cwd,
            env=environment,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            creationflags=getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0) | _CREATE_SUSPENDED,
        )
        _assign_and_resume(process, job)
        return process, job
    except BaseException:
        _cleanup_failed_spawn(process, job)
        raise


def close_windows_hook_job(job: WindowsHookJob) -> None:
    """Close the job, deterministically terminating any remaining descendants."""

    try:
        job.close()
    except OSError:
        with contextlib.suppress(OSError):
            job.terminate()
        job.close()


def _kernel32():  # type: ignore[no-untyped-def]
    win_dll = getattr(ctypes, "WinDLL", None)
    if win_dll is None:
        raise OSError("windows_job_api_unavailable")
    return win_dll("kernel32", use_last_error=True)


def _create_job() -> WindowsHookJob:
    kernel32 = _kernel32()
    create_job = kernel32.CreateJobObjectW
    create_job.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
    create_job.restype = wintypes.HANDLE
    set_information = kernel32.SetInformationJobObject
    set_information.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
    set_information.restype = wintypes.BOOL
    raw_handle = create_job(None, None)
    if raw_handle is None:
        raise OSError(ctypes.get_last_error(), "CreateJobObjectW failed")
    job = WindowsHookJob(handle=int(raw_handle))
    try:
        limits = _ExtendedLimitInformation()
        limits.basic_limit_information.limit_flags = _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if not set_information(
            wintypes.HANDLE(job.handle),
            _JOB_OBJECT_EXTENDED_LIMIT_INFORMATION_CLASS,
            ctypes.byref(limits),
            ctypes.sizeof(limits),
        ):
            raise OSError(ctypes.get_last_error(), "SetInformationJobObject failed")
        return job
    except BaseException:
        with contextlib.suppress(OSError):
            job.close()
        raise


def _assign_and_resume(process: subprocess.Popen[bytes], job: WindowsHookJob) -> None:
    kernel32 = _kernel32()
    assign_process = kernel32.AssignProcessToJobObject
    assign_process.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    assign_process.restype = wintypes.BOOL
    is_process_in_job = kernel32.IsProcessInJob
    is_process_in_job.argtypes = [wintypes.HANDLE, wintypes.HANDLE, ctypes.POINTER(wintypes.BOOL)]
    is_process_in_job.restype = wintypes.BOOL
    process_handle = _process_handle(process)
    if not assign_process(wintypes.HANDLE(job.handle), wintypes.HANDLE(process_handle)):
        raise OSError(ctypes.get_last_error(), "AssignProcessToJobObject failed")
    assigned = wintypes.BOOL()
    if (
        not is_process_in_job(
            wintypes.HANDLE(process_handle),
            wintypes.HANDLE(job.handle),
            ctypes.byref(assigned),
        )
        or not assigned.value
    ):
        raise OSError(ctypes.get_last_error(), "IsProcessInJob failed")
    _resume_primary_thread(process.pid)


def _process_handle(process: subprocess.Popen[bytes]) -> int:
    raw_handle = getattr(process, "_handle", None)
    if not isinstance(raw_handle, int) or raw_handle <= 0:
        raise OSError("Windows process handle is unavailable")
    return raw_handle


def _resume_primary_thread(process_id: int) -> None:
    kernel32 = _kernel32()
    create_snapshot = kernel32.CreateToolhelp32Snapshot
    create_snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    create_snapshot.restype = wintypes.HANDLE
    thread_first = kernel32.Thread32First
    thread_first.argtypes = [wintypes.HANDLE, ctypes.POINTER(_ThreadEntry32)]
    thread_first.restype = wintypes.BOOL
    thread_next = kernel32.Thread32Next
    thread_next.argtypes = [wintypes.HANDLE, ctypes.POINTER(_ThreadEntry32)]
    thread_next.restype = wintypes.BOOL
    open_thread = kernel32.OpenThread
    open_thread.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    open_thread.restype = wintypes.HANDLE
    resume_thread = kernel32.ResumeThread
    resume_thread.argtypes = [wintypes.HANDLE]
    resume_thread.restype = wintypes.DWORD
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = [wintypes.HANDLE]
    close_handle.restype = wintypes.BOOL

    snapshot = create_snapshot(_TH32CS_SNAPTHREAD, 0)
    invalid_handle = ctypes.c_void_p(-1).value
    if snapshot in {None, invalid_handle}:
        raise OSError(ctypes.get_last_error(), "CreateToolhelp32Snapshot failed")
    thread_ids: list[int] = []
    enumeration_error = 0
    try:
        entry = _ThreadEntry32()
        entry.dwSize = ctypes.sizeof(entry)
        ctypes.set_last_error(0)
        has_entry = bool(thread_first(snapshot, ctypes.byref(entry)))
        first_error = 0 if has_entry else ctypes.get_last_error()
        while has_entry:
            if int(entry.th32OwnerProcessID) == process_id:
                thread_ids.append(int(entry.th32ThreadID))
            entry.dwSize = ctypes.sizeof(entry)
            ctypes.set_last_error(0)
            has_entry = bool(thread_next(snapshot, ctypes.byref(entry)))
            if not has_entry:
                enumeration_error = ctypes.get_last_error()
    finally:
        _ = close_handle(snapshot)
    if first_error:
        raise OSError(first_error, "Thread32First failed")
    if enumeration_error != _ERROR_NO_MORE_FILES:
        raise OSError(enumeration_error, "Thread32Next failed")
    if len(thread_ids) != 1:
        raise OSError("suspended Windows hook process primary thread is ambiguous")

    thread_handle = open_thread(_THREAD_SUSPEND_RESUME, False, thread_ids[0])
    if not thread_handle:
        raise OSError(ctypes.get_last_error(), "OpenThread failed")
    try:
        previous_suspend_count = int(resume_thread(thread_handle))
    finally:
        _ = close_handle(thread_handle)
    if previous_suspend_count == _RESUME_THREAD_FAILED:
        raise OSError(ctypes.get_last_error(), "ResumeThread failed")
    if previous_suspend_count != 1:
        raise OSError("suspended Windows hook process had an unexpected suspend count")


def _cleanup_failed_spawn(process: subprocess.Popen[bytes] | None, job: WindowsHookJob) -> None:
    with contextlib.suppress(OSError):
        job.terminate()
    if process is not None:
        if process.poll() is None:
            with contextlib.suppress(OSError):
                process.kill()
        with contextlib.suppress(subprocess.TimeoutExpired):
            process.wait(timeout=1)
        _close_process_streams(process)
    with contextlib.suppress(OSError):
        close_windows_hook_job(job)


def _close_process_streams(process: subprocess.Popen[bytes]) -> None:
    for stream in (process.stdin, process.stdout, process.stderr):
        if stream is not None:
            with contextlib.suppress(OSError):
                stream.close()


__all__ = [
    "WindowsHookJob",
    "close_windows_hook_job",
    "spawn_windows_hook_process",
]
