"""Observe a worker and every orphaned descendant inside a Linux subreaper.

This module runs only in a fresh, single-threaded supervisor process. A normal
worker exit followed by waitpid(-1, __WALL) returning ECHILD closes the kernel
descendant boundary, including children that changed process group/session.
It never turns forced cleanup, a timeout, or output truncation into that proof.
"""

from __future__ import annotations

import ctypes
import hashlib
import os
import selectors
import signal
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

_PR_SET_CHILD_SUBREAPER = 36
_PR_GET_CHILD_SUBREAPER = 37
_WAIT_ALL = 0x40000000
_MAX_REAPED = 256


@dataclass(frozen=True)
class OwnedResult:
    stdout: bytes
    stderr: bytes
    returncode: int | None
    evidence: dict[str, Any]


def _children_empty() -> bool:
    try:
        os.waitid(os.P_ALL, 0, os.WEXITED | os.WNOHANG | os.WNOWAIT | _WAIT_ALL)
    except ChildProcessError:
        return True
    return False


def _subreaper() -> None:
    if sys.platform != "linux" or threading.active_count() != 1 or not _children_empty():
        raise RuntimeError("transition_owner_initial_boundary_invalid")
    # Explicit SIG_IGN/SA_NOCLDWAIT would discard statuses. Install SIG_DFL
    # before spawning; this supervisor never installs another handler/reaper.
    signal.signal(signal.SIGCHLD, signal.SIG_DFL)
    libc = ctypes.CDLL(None, use_errno=True)
    prctl = libc.prctl
    prctl.restype = ctypes.c_int
    if prctl(_PR_SET_CHILD_SUBREAPER, ctypes.c_ulong(1), 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "transition_owner_set_subreaper_failed")
    enabled = ctypes.c_int()
    if prctl(_PR_GET_CHILD_SUBREAPER, ctypes.byref(enabled), 0, 0, 0) != 0 or enabled.value != 1:
        raise OSError(ctypes.get_errno(), "transition_owner_get_subreaper_failed")


def _birth(pid: int) -> str:
    fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
    return fields[19]


def _kill_owned_children() -> int:
    """Failure cleanup only: pin unreaped direct children before signalling.

    No other thread or signal handler reaps these children. Their PIDs cannot
    be reused between the kernel children-list read and pidfd_open. Reparented
    grandchildren enter the same owned list on the next bounded iteration.
    """
    try:
        children = Path("/proc/thread-self/children").read_text().split()
    except FileNotFoundError:
        # Some kernels omit CONFIG_PROC_CHILDREN. This fallback is used only
        # after proof has failed, solely to clean up our own unreaped children.
        # A process-table inventory is never used to certify quiescence.
        if int(Path("/proc/self/stat").read_text().split(" ", 1)[0]) != os.getpid():
            raise RuntimeError("transition_owner_proc_namespace_mismatch") from None
        children: list[str] = []
        with os.scandir("/proc") as entries:
            for index, entry in enumerate(entries):
                if index > 65536:
                    raise RuntimeError("transition_owner_inventory_limit") from None
                if not entry.name.isdecimal():
                    continue
                try:
                    fields = (Path(entry.path) / "stat").read_text().rsplit(")", 1)[1].split()
                except (FileNotFoundError, ProcessLookupError):
                    continue
                if int(fields[1]) == os.getpid():
                    children.append(entry.name)
    if len(children) > _MAX_REAPED:
        raise RuntimeError("transition_owner_child_limit")
    count = 0
    for value in children:
        descriptor = os.pidfd_open(int(value))
        try:
            try:
                signal.pidfd_send_signal(descriptor, signal.SIGKILL)
                count += 1
            except ProcessLookupError:
                # The child exited but remains ours and unreaped. The next
                # waitpid observes it; no numeric PID signal is substituted.
                pass
        finally:
            os.close(descriptor)
    return count


def run_owned(
    arguments: tuple[str, ...],
    *,
    cwd: Path,
    environment: dict[str, str],
    timeout_seconds: float = 180,
    drain_seconds: float = 5,
    output_limit: int = 256 * 1024,
) -> OwnedResult:
    """Run one exact argv; retain the failed prefix even if ownership fails."""
    if sys.platform == "win32":
        from scripts.ci.installed_transition_windows_owner import run_owned_windows

        return run_owned_windows(
            arguments,
            cwd=cwd,
            environment=environment,
            timeout_seconds=timeout_seconds,
            drain_seconds=drain_seconds,
            output_limit=output_limit,
        )
    _subreaper()
    if not 0 < timeout_seconds <= 180 or not 0 < drain_seconds <= 5 or not 0 < output_limit <= 256 * 1024:
        raise ValueError("transition_owner_bounds_invalid")
    evidence: dict[str, Any] = {
        "mechanism": "linux_child_subreaper",
        "platform": "linux",
        "verified": False,
        "initial_children_empty": True,
        "enabled_before_spawn": True,
        "worker_exit_observed": False,
        "descendants_exhausted": False,
        "termination_signals_sent": 0,
        "adopted_signalled_exits": 0,
        "reaped_process_count": 0,
        "timed_out": False,
        "limit_exceeded": False,
        "containment_failed": False,
    }
    captured = {"stdout": bytearray(), "stderr": bytearray()}
    process = subprocess.Popen(
        arguments,
        cwd=cwd,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
        close_fds=True,
    )
    assert process.stdout is not None and process.stderr is not None
    selector = selectors.DefaultSelector()
    deadline = time.monotonic() + timeout_seconds
    cleanup_deadline = None
    worker_status = None
    failed = False
    total_bytes = 0
    statuses = hashlib.sha256()
    try:
        # Popen's exec-error pipe has already witnessed successful exec. The
        # direct child remains unreaped, retaining its identity through exit.
        evidence.update(worker_pid=process.pid, worker_birth=_birth(process.pid))
        for channel, stream in (("stdout", process.stdout), ("stderr", process.stderr)):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, channel)
        while True:
            exhausted = False
            while True:
                try:
                    pid, status = os.waitpid(-1, os.WNOHANG | _WAIT_ALL)
                except ChildProcessError:
                    exhausted = True
                    break
                if pid == 0:
                    break
                evidence["reaped_process_count"] += 1
                statuses.update(f"{pid}:{status};".encode("ascii"))
                if pid == process.pid and worker_status is None:
                    worker_status = status
                    process.returncode = os.waitstatus_to_exitcode(status)
                    evidence["worker_exit_observed"] = True
                    deadline = min(deadline, time.monotonic() + drain_seconds)
                elif os.WIFSIGNALED(status):
                    evidence["adopted_signalled_exits"] += 1
                    failed = True
                if evidence["reaped_process_count"] > _MAX_REAPED:
                    evidence["limit_exceeded"] = True
                    failed = True
                    break
            for key, _events in selector.select(0.01):
                data = os.read(key.fd, 65536)
                if not data:
                    selector.unregister(key.fileobj)
                    continue
                remaining = max(0, output_limit - total_bytes)
                captured[key.data].extend(data[:remaining])
                total_bytes += len(data)
                if total_bytes > output_limit:
                    evidence["limit_exceeded"] = True
                    failed = True
            if time.monotonic() >= deadline:
                evidence["timed_out"] = True
                failed = True
            if exhausted and not selector.get_map():
                evidence["descendants_exhausted"] = True
                break
            if failed:
                if cleanup_deadline is None:
                    cleanup_deadline = time.monotonic() + 5
                evidence["termination_signals_sent"] += _kill_owned_children()
                if time.monotonic() >= cleanup_deadline:
                    evidence["containment_failed"] = True
                    break
        evidence["worker_return_code"] = process.returncode
        evidence["exit_statuses_sha256"] = statuses.hexdigest()
        evidence["verified"] = (
            not failed
            and worker_status is not None
            and os.WIFEXITED(worker_status)
            and evidence["descendants_exhausted"]
            and evidence["termination_signals_sent"] == 0
        )
    except Exception as error:
        # Error paths remain failures even when owned cleanup later succeeds.
        evidence["containment_failed"] = True
        evidence["observation_failure"] = type(error).__name__
        cleanup_deadline = time.monotonic() + 5
        try:
            while time.monotonic() < cleanup_deadline and not _children_empty():
                evidence["termination_signals_sent"] += _kill_owned_children()
                while True:
                    try:
                        pid, status = os.waitpid(-1, os.WNOHANG | _WAIT_ALL)
                    except ChildProcessError:
                        break
                    if pid == 0:
                        break
                    if pid == process.pid and process.returncode is None:
                        process.returncode = os.waitstatus_to_exitcode(status)
                time.sleep(0.01)
        except (OSError, RuntimeError) as cleanup_error:
            evidence["cleanup_failure"] = type(cleanup_error).__name__
    finally:
        selector.close()
        process.stdout.close()
        process.stderr.close()
    return OwnedResult(bytes(captured["stdout"]), bytes(captured["stderr"]), process.returncode, evidence)
