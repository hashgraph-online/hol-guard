"""Observe an unchanged worker inside a non-breakaway Windows Job Object.

Use the existing suspended-spawn/assignment primitives from the collector's
pinned checkout. Query the retained Job handle until no processes remain,
before closing it. Any forced cleanup stays a failed observation.
"""

from __future__ import annotations

import ctypes
import hashlib
import json
import os
import subprocess
import threading
import time
from pathlib import Path
from typing import Any, BinaryIO

from scripts.ci.installed_transition_owner import OwnedResult
from scripts.ci.installed_transition_windows_api import source_module


class _Accounting(ctypes.Structure):
    _fields_ = [
        ("user_time", ctypes.c_int64),
        ("kernel_time", ctypes.c_int64),
        ("period_user_time", ctypes.c_int64),
        ("period_kernel_time", ctypes.c_int64),
        ("page_faults", ctypes.c_uint32),
        ("total", ctypes.c_uint32),
        ("active", ctypes.c_uint32),
        ("terminated", ctypes.c_uint32),
    ]


class _FileTime(ctypes.Structure):
    _fields_ = [("low", ctypes.c_uint32), ("high", ctypes.c_uint32)]


def _job_api() -> Any:
    return source_module("guard.codex_hook_windows_job")


def _query(api: Any, job: Any, information_class: int, value: ctypes.Structure) -> None:
    function = api._kernel32().QueryInformationJobObject
    function.argtypes = [
        ctypes.c_void_p,
        ctypes.c_int,
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_uint32),
    ]
    function.restype = ctypes.c_int
    written = ctypes.c_uint32()
    if not function(job.handle, information_class, ctypes.byref(value), ctypes.sizeof(value), ctypes.byref(written)):
        raise OSError(ctypes.get_last_error(), "transition_owner_windows_query_failed")
    if written.value != ctypes.sizeof(value):
        raise OSError("transition_owner_windows_query_size_invalid")


def _accounting(api: Any, job: Any) -> dict[str, int]:
    value = _Accounting()
    _query(api, job, 1, value)
    return {"total": int(value.total), "active": int(value.active), "terminated": int(value.terminated)}


def _birth(api: Any, process: subprocess.Popen[bytes]) -> str:
    values = [_FileTime() for _ in range(4)]
    function = api._kernel32().GetProcessTimes
    function.argtypes = [ctypes.c_void_p, *([ctypes.POINTER(_FileTime)] * 4)]
    function.restype = ctypes.c_int
    if not function(api._process_handle(process), *(ctypes.byref(value) for value in values)):
        raise OSError(ctypes.get_last_error(), "transition_owner_windows_identity_failed")
    return str((values[0].high << 32) | values[0].low)


def run_owned_windows(
    arguments: tuple[str, ...],
    *,
    cwd: Path,
    environment: dict[str, str],
    timeout_seconds: float = 180,
    drain_seconds: float = 5,
    output_limit: int = 256 * 1024,
) -> OwnedResult:
    if os.name != "nt" or not 0 < timeout_seconds <= 180 or not 0 < drain_seconds <= 5:
        raise ValueError("transition_owner_windows_platform_or_bounds_invalid")
    if not 0 < output_limit <= 256 * 1024:
        raise ValueError("transition_owner_windows_capture_bound_invalid")
    deadline = time.monotonic() + timeout_seconds
    api = _job_api()
    job = api._create_job(allow_breakaway=False, kill_on_close=True)
    process = None
    readers: list[threading.Thread] = []
    captured = {"stdout": bytearray(), "stderr": bytearray()}
    capture_lock = threading.Lock()
    count = 0
    stream_failures: list[str] = []
    ended = {"stdout": False, "stderr": False}
    evidence: dict[str, Any] = {
        "mechanism": "windows_job_object",
        "platform": "win32",
        "verified": False,
        "initial_children_empty": False,
        "enabled_before_spawn": False,
        "worker_exit_observed": False,
        "descendants_exhausted": False,
        "termination_requests": 0,
        "total_process_count": 0,
        "timed_out": False,
        "limit_exceeded": False,
        "containment_failed": False,
        "breakaway_disabled": False,
        "limit_terminated_count": 0,
    }

    def read(channel: str, stream: BinaryIO) -> None:
        nonlocal count
        try:
            while chunk := stream.read(65536):
                with capture_lock:
                    captured[channel].extend(chunk[: max(0, output_limit - count)])
                    count += len(chunk)
                    if count > output_limit:
                        evidence["limit_exceeded"] = True
            ended[channel] = True
        except OSError as error:
            stream_failures.append(type(error).__name__)

    try:
        initial = _accounting(api, job)
        limits = api._ExtendedLimitInformation()
        _query(api, job, 9, limits)
        flags = int(limits.basic_limit_information.limit_flags)
        if initial != {"total": 0, "active": 0, "terminated": 0} or flags != 0x2000:
            raise RuntimeError("transition_owner_windows_initial_job_invalid")
        evidence.update(initial_children_empty=True, enabled_before_spawn=True, breakaway_disabled=True)
        process = subprocess.Popen(
            arguments,
            cwd=cwd,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            creationflags=api._CREATE_SUSPENDED | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0),
        )
        assert process.stdout is not None and process.stderr is not None
        evidence.update(worker_pid=process.pid, worker_birth=_birth(api, process))
        api._assign_and_resume(process, job)
        for channel, stream in (("stdout", process.stdout), ("stderr", process.stderr)):
            thread = threading.Thread(target=read, args=(channel, stream), daemon=True)
            readers.append(thread)
            thread.start()
        failure_deadline = None
        failed = False
        while True:
            returncode = process.poll()
            if returncode is not None and not evidence["worker_exit_observed"]:
                evidence.update(worker_exit_observed=True, worker_return_code=returncode)
                deadline = min(deadline, time.monotonic() + drain_seconds)
            accounting = _accounting(api, job)
            evidence.update(total_process_count=accounting["total"], limit_terminated_count=accounting["terminated"])
            if accounting["total"] > 256 or accounting["terminated"] != 0 or stream_failures:
                failed = True
            if time.monotonic() >= deadline:
                evidence["timed_out"] = True
                failed = True
            if evidence["limit_exceeded"]:
                failed = True
            if accounting["active"] == 0 and returncode is not None and all(ended.values()):
                evidence["descendants_exhausted"] = True
                break
            if failed:
                if failure_deadline is None:
                    failure_deadline = time.monotonic() + 5
                    evidence["termination_requests"] += 1
                    job.terminate()
                if time.monotonic() >= failure_deadline:
                    evidence["containment_failed"] = True
                    break
            time.sleep(0.01)
        for thread in readers:
            thread.join(timeout=0.1)
        # Query the retained handle once more before CloseHandle can activate
        # kill-on-close; emptiness must be observed independently of cleanup.
        final = _accounting(api, job)
        if time.monotonic() >= deadline:
            evidence["timed_out"] = True
            failed = True
        evidence["job_empty_before_close"] = final["active"] == 0
        evidence["lifecycle_sha256"] = hashlib.sha256(json.dumps(final, sort_keys=True).encode()).hexdigest()
        evidence["exit_statuses_sha256"] = hashlib.sha256(json.dumps([process.returncode]).encode()).hexdigest()
        evidence["verified"] = (
            not failed
            and not evidence["limit_exceeded"]
            and not stream_failures
            and evidence["worker_exit_observed"]
            and evidence["descendants_exhausted"]
            and final["active"] == 0
            and final["terminated"] == 0
            and evidence["termination_requests"] == 0
            and not any(thread.is_alive() for thread in readers)
        )
    except Exception as error:
        evidence.update(verified=False, containment_failed=True, observation_failure=type(error).__name__)
        evidence["termination_requests"] += 1
        # Production cleanup uses the retained Job/process handles, including
        # the suspended-child case where assignment failed before execution.
        if not readers:
            api._cleanup_failed_spawn(process, job)
        else:
            try:
                job.terminate()
                if process is not None:
                    process.wait(timeout=1)
                join_deadline = time.monotonic() + 1
                for thread in readers:
                    thread.join(timeout=max(0, join_deadline - time.monotonic()))
            except (OSError, subprocess.TimeoutExpired) as cleanup_error:
                evidence["cleanup_failure"] = type(cleanup_error).__name__
    finally:
        if not job.closed:
            try:
                job.close()
            except OSError:
                evidence.update(verified=False, containment_failed=True)
        if process is not None and not any(thread.is_alive() for thread in readers):
            for stream in (process.stdin, process.stdout, process.stderr):
                if stream is not None:
                    stream.close()
    with capture_lock:
        return OwnedResult(
            bytes(captured["stdout"]),
            bytes(captured["stderr"]),
            process.returncode if process is not None else None,
            evidence,
        )
