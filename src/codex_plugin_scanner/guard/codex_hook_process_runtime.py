"""Bounded process IO and lifecycle helpers for isolated Codex hooks."""

from __future__ import annotations

import subprocess
import threading
import time
from collections.abc import Callable, Sequence
from typing import BinaryIO

from .codex_hook_windows_job import WindowsHookJob

_HOOK_PROCESS_REAP_TIMEOUT_SECONDS = 0.2
_HOOK_PROCESS_FINAL_REAP_TIMEOUT_SECONDS = 0.1
_HOOK_PROCESS_IO_THREAD_JOIN_TIMEOUT_SECONDS = 0.05
_HOOK_PROCESS_FINAL_IO_JOIN_TIMEOUT_SECONDS = 1.0

_TerminateHookProcess = Callable[[subprocess.Popen[bytes], WindowsHookJob | None], bool]
_QuarantineHookProcess = Callable[[subprocess.Popen[bytes], WindowsHookJob | None, Sequence[threading.Thread]], None]
_CloseProcessStreams = Callable[[subprocess.Popen[bytes]], None]
_CloseWindowsJob = Callable[[WindowsHookJob], None]


def _drain_hook_stream(
    stream: BinaryIO,
    target: bytearray,
    *,
    output_limit: int,
    output_count: list[int],
    output_lock: threading.Lock,
    output_limit_exceeded: threading.Event,
) -> None:
    while chunk := stream.read(64 * 1024):
        with output_lock:
            remaining = max(0, output_limit - output_count[0])
            accepted = chunk[:remaining]
            output_count[0] += len(chunk)
            if accepted:
                target.extend(accepted)
            if output_count[0] > output_limit:
                output_limit_exceeded.set()


def _write_hook_input(stream: BinaryIO | None, input_text: str) -> None:
    if stream is None:
        return
    try:
        stream.write(input_text.encode("utf-8"))
        stream.flush()
    except (BrokenPipeError, OSError):
        pass
    finally:
        stream.close()


def start_hook_io(
    process: subprocess.Popen[bytes],
    *,
    input_text: str,
    output_limit: int,
) -> tuple[bytearray, bytearray, threading.Event, threading.Lock, list[threading.Thread]]:
    """Start bounded readers and the input writer for one child process."""
    stdout_bytes, stderr_bytes = bytearray(), bytearray()
    output_count = [0]
    output_lock = threading.Lock()
    output_limit_exceeded = threading.Event()
    reader_kwargs = {
        "output_limit": output_limit,
        "output_count": output_count,
        "output_lock": output_lock,
        "output_limit_exceeded": output_limit_exceeded,
    }
    readers = [
        threading.Thread(
            target=_drain_hook_stream,
            args=(process.stdout, stdout_bytes),
            kwargs=reader_kwargs,
            daemon=True,
        ),
        threading.Thread(
            target=_drain_hook_stream,
            args=(process.stderr, stderr_bytes),
            kwargs=reader_kwargs,
            daemon=True,
        ),
    ]
    writer = threading.Thread(target=_write_hook_input, args=(process.stdin, input_text), daemon=True)
    for thread in readers:
        thread.start()
    writer.start()
    return stdout_bytes, stderr_bytes, output_limit_exceeded, output_lock, [writer, *readers]


def wait_for_hook_process(
    process: subprocess.Popen[bytes],
    windows_job: WindowsHookJob | None,
    *,
    deadline: float,
    stop_event: threading.Event | None,
    output_limit_exceeded: threading.Event,
    terminate: _TerminateHookProcess,
) -> tuple[int | None, bool, bool, bool]:
    """Wait, enforce the deadline, and terminate failed process trees."""
    timed_out = False
    containment_confirmed = True
    termination_requested = False
    while process.poll() is None:
        if stop_event is not None and stop_event.is_set():
            termination_requested = True
            containment_confirmed = terminate(process, windows_job)
            break
        if output_limit_exceeded.is_set():
            termination_requested = True
            containment_confirmed = terminate(process, windows_job)
            break
        if time.monotonic() >= deadline:
            timed_out = True
            termination_requested = True
            containment_confirmed = terminate(process, windows_job)
            break
        time.sleep(0.01)
    try:
        returncode = process.wait(timeout=_HOOK_PROCESS_REAP_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        termination_requested = True
        containment_confirmed = terminate(process, windows_job) and containment_confirmed
        try:
            returncode = process.wait(timeout=_HOOK_PROCESS_FINAL_REAP_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired:
            containment_confirmed = False
            returncode = None
    if not timed_out and time.monotonic() >= deadline:
        timed_out = True
    result_failed = (
        returncode is None
        or returncode != 0
        or output_limit_exceeded.is_set()
        or timed_out
        or (stop_event is not None and stop_event.is_set())
    )
    if result_failed and (not termination_requested or not containment_confirmed):
        termination_requested = True
        containment_confirmed = terminate(process, windows_job) and containment_confirmed
    return returncode, timed_out, containment_confirmed, termination_requested


def join_and_cleanup_hook_process(
    process: subprocess.Popen[bytes],
    windows_job: WindowsHookJob | None,
    io_threads: Sequence[threading.Thread],
    *,
    containment_confirmed: bool,
    termination_requested: bool,
    terminate: _TerminateHookProcess,
    quarantine: _QuarantineHookProcess,
    close_streams: _CloseProcessStreams,
    close_job: _CloseWindowsJob,
) -> tuple[WindowsHookJob | None, bool, bool]:
    """Join IO, close a surviving job, and quarantine only unresolved failures."""
    io_join_deadline = time.monotonic() + _HOOK_PROCESS_IO_THREAD_JOIN_TIMEOUT_SECONDS
    for thread in io_threads:
        thread.join(timeout=max(0.0, io_join_deadline - time.monotonic()))
    if any(thread.is_alive() for thread in io_threads):
        if not termination_requested or not containment_confirmed:
            termination_requested = True
            containment_confirmed = terminate(process, windows_job) and containment_confirmed
        final_io_join_deadline = time.monotonic() + _HOOK_PROCESS_FINAL_IO_JOIN_TIMEOUT_SECONDS
        for thread in io_threads:
            thread.join(timeout=max(0.0, final_io_join_deadline - time.monotonic()))
        if any(thread.is_alive() for thread in io_threads):
            containment_confirmed = False
    job_cleanup_failed = False
    if any(thread.is_alive() for thread in io_threads):
        containment_confirmed = False
    elif windows_job is not None and containment_confirmed:
        try:
            close_job(windows_job)
        except OSError:
            job_cleanup_failed = True
            containment_confirmed = False
            _ = terminate(process, windows_job)
        else:
            windows_job = None
    if not containment_confirmed:
        quarantine(process, windows_job, io_threads)
    if all(not thread.is_alive() for thread in io_threads):
        close_streams(process)
    return windows_job, containment_confirmed, job_cleanup_failed


__all__ = [
    "_HOOK_PROCESS_FINAL_IO_JOIN_TIMEOUT_SECONDS",
    "_HOOK_PROCESS_FINAL_REAP_TIMEOUT_SECONDS",
    "_HOOK_PROCESS_IO_THREAD_JOIN_TIMEOUT_SECONDS",
    "_HOOK_PROCESS_REAP_TIMEOUT_SECONDS",
    "join_and_cleanup_hook_process",
    "start_hook_io",
    "wait_for_hook_process",
]
