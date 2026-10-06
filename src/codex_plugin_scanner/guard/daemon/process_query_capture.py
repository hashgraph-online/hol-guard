"""Drain process-query stdout within its original bounded deadline."""

from __future__ import annotations

import subprocess
import threading
import time
from collections.abc import Callable
from contextlib import suppress
from typing import BinaryIO, cast

CaptureStdout = Callable[[BinaryIO, bytearray, int, threading.Event, list[OSError | ValueError]], None]


def bounded_process_query_stdout(
    command: list[str],
    *,
    timeout_seconds: float,
    output_limit_bytes: int,
    monitor_interval_seconds: float,
    cleanup_timeout_seconds: float,
    spawn: Callable[[list[str]], subprocess.Popen[bytes]],
    capture_stdout: CaptureStdout,
    terminate: Callable[[subprocess.Popen[bytes]], None],
) -> str | None:
    """Reject failed, oversized or expired output, retaining timeout decisions."""

    if timeout_seconds <= 0 or output_limit_bytes < 0:
        return None
    try:
        process = spawn(command)
    except (OSError, subprocess.SubprocessError, ValueError):
        return None
    stdout = cast(BinaryIO | None, getattr(process, "stdout", None))
    if stdout is None:
        terminate(process)
        return None

    captured = bytearray()
    overflow = threading.Event()
    errors: list[OSError | ValueError] = []
    reader = threading.Thread(
        target=capture_stdout,
        args=(stdout, captured, output_limit_bytes, overflow, errors),
        name="guard-daemon-process-query",
        daemon=True,
    )
    timed_out = False
    reader_started = False
    deadline = time.monotonic() + timeout_seconds
    try:
        reader.start()
        reader_started = True
        while process.poll() is None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                break
            if overflow.wait(min(monitor_interval_seconds, remaining)):
                break
        if process.poll() is not None and reader.is_alive():
            # Scheduling lag may delay a completed child's output reader.
            # Cleanup grace must not truncate the remaining query budget.
            reader.join(timeout=max(0.0, deadline - time.monotonic()))
            timed_out = timed_out or reader.is_alive()
    except BaseException:
        terminate(process)
        raise
    finally:
        if timed_out or overflow.is_set() or process.poll() is None or reader.is_alive():
            terminate(process)
        if reader_started:
            reader.join(timeout=cleanup_timeout_seconds)
            if reader.is_alive():
                with suppress(OSError, ValueError):
                    stdout.close()
                reader.join(timeout=cleanup_timeout_seconds)

    if timed_out or overflow.is_set() or errors or reader.is_alive():
        return None
    try:
        returncode = process.wait(timeout=cleanup_timeout_seconds)
    except subprocess.TimeoutExpired:
        terminate(process)
        return None
    if returncode != 0:
        return None
    try:
        return bytes(captured).decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return None
