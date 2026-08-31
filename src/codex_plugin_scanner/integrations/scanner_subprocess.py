"""Bounded subprocess execution for optional third-party scanners."""

from __future__ import annotations

import contextlib
import ctypes
import errno
import json
import math
import os
import platform
import select
import signal
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Protocol, cast

if os.name == "posix":
    import resource as _resource
else:
    _resource = None

MAX_SCANNER_OUTPUT_BYTES = 8 * 1024 * 1024
_MAX_SCANNER_MEMORY_BYTES = 4 * 1024 * 1024 * 1024
_MACOS_SCANNER_SANDBOX = "(version 1)(allow default)(deny process-fork)"
_POSIX_LOCKDOWN_BOOTSTRAP = (
    "from codex_plugin_scanner.integrations.scanner_subprocess import "
    "_exec_posix_scanner_with_lockdown; _exec_posix_scanner_with_lockdown()"
)
_INHERITED_RUNTIME_ENV = frozenset(
    {
        "COLORTERM",
        "COMSPEC",
        "HOME",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "LOGNAME",
        "NO_COLOR",
        "PATH",
        "PATHEXT",
        "PYTHONIOENCODING",
        "SHELL",
        "SSL_CERT_DIR",
        "SSL_CERT_FILE",
        "SYSTEMROOT",
        "TEMP",
        "TERM",
        "TMP",
        "TMPDIR",
        "USER",
        "WINDIR",
    }
)


@dataclass(frozen=True, slots=True)
class ScannerProcessResult:
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False


class _WindowsJob(Protocol):
    def terminate(self) -> None: ...

    def close(self) -> None: ...


class _Kqueue(Protocol):
    def control(self, changelist: list[object], max_events: int, timeout: float) -> list[object]: ...

    def close(self) -> None: ...


class _SockFilter(ctypes.Structure):
    _fields_ = (
        ("code", ctypes.c_ushort),
        ("jt", ctypes.c_ubyte),
        ("jf", ctypes.c_ubyte),
        ("k", ctypes.c_uint32),
    )


class _SockFprog(ctypes.Structure):
    _fields_ = (("length", ctypes.c_ushort), ("filters", ctypes.POINTER(_SockFilter)))


def scrubbed_scanner_env(
    *,
    explicit: Mapping[str, str] | None = None,
    allowed_secret_names: frozenset[str] = frozenset(),
) -> dict[str, str]:
    allowed = _INHERITED_RUNTIME_ENV | allowed_secret_names
    env = {key: value for key, value in os.environ.items() if key in allowed}
    if explicit:
        env.update(explicit)
    return env


def run_bounded_scanner_process(
    argv: Sequence[str],
    *,
    env: Mapping[str, str],
    timeout_seconds: float,
) -> ScannerProcessResult:
    with tempfile.TemporaryDirectory(prefix="hol-guard-scanner-") as working_directory:
        process, windows_job = _spawn_scanner_process(
            argv,
            env=env,
            timeout_seconds=timeout_seconds,
            working_directory=Path(working_directory),
        )
        stdout_buffer = bytearray()
        stderr_buffer = bytearray()
        stdout_thread = _start_bounded_drain(cast(BinaryIO | None, process.stdout), stdout_buffer)
        stderr_thread = _start_bounded_drain(cast(BinaryIO | None, process.stderr), stderr_buffer)
        if process.stdin is not None:
            process.stdin.close()
        deadline = time.monotonic() + timeout_seconds
        timed_out = False
        try:
            if os.name == "posix":
                timed_out = not _wait_for_posix_leader_without_reaping(process, deadline)
                _terminate_process_group(process)
                process.wait(timeout=1)
            else:
                process.wait(timeout=_remaining_deadline(deadline))
        except subprocess.TimeoutExpired:
            timed_out = True
            _terminate_process_group(process, windows_job=windows_job)
            try:
                process.wait(timeout=max(_remaining_deadline(deadline), 0.1))
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=1)
        finally:
            # A scanner leader may exit while descendants retain the captured
            # pipes. Close the whole sandbox before waiting for EOF.
            if windows_job is not None:
                _close_windows_job(windows_job)
            elif process.returncode is None:
                _terminate_process_group(process)
            _finish_bounded_drain(stdout_thread, cast(BinaryIO | None, process.stdout), deadline)
            _finish_bounded_drain(stderr_thread, cast(BinaryIO | None, process.stderr), deadline)
        stdout = bytes(stdout_buffer).decode("utf-8", errors="replace")
        stderr = bytes(stderr_buffer).decode("utf-8", errors="replace")
    if process.returncode is None:
        raise RuntimeError("scanner subprocess was not reaped")
    return ScannerProcessResult(process.returncode, stdout, stderr, timed_out)


def _remaining_deadline(deadline: float) -> float:
    return max(deadline - time.monotonic(), 0.001)


def _wait_for_posix_leader_without_reaping(process: subprocess.Popen[bytes], deadline: float) -> bool:
    waitid = getattr(os, "waitid", None)
    if callable(waitid) and all(hasattr(os, name) for name in ("P_PID", "WEXITED", "WNOHANG", "WNOWAIT")):
        flags = os.WEXITED | os.WNOHANG | os.WNOWAIT
        waitid_fn = cast(Callable[[int, int, int], object | None], waitid)
        return _wait_for_posix_leader_with_waitid(process, deadline, waitid_fn, flags)
    return _wait_for_posix_leader_with_kqueue(process, deadline)


def _wait_for_posix_leader_with_waitid(
    process: subprocess.Popen[bytes],
    deadline: float,
    waitid: Callable[[int, int, int], object | None],
    flags: int,
) -> bool:
    while True:
        try:
            if waitid(os.P_PID, process.pid, flags) is not None:
                return True
        except ChildProcessError:
            return False
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        time.sleep(min(remaining, 0.01))


def _wait_for_posix_leader_with_kqueue(process: subprocess.Popen[bytes], deadline: float) -> bool:
    kqueue_factory = getattr(select, "kqueue", None)
    kevent_factory = getattr(select, "kevent", None)
    constants = (
        getattr(select, "KQ_FILTER_PROC", None),
        getattr(select, "KQ_EV_ADD", None),
        getattr(select, "KQ_EV_ONESHOT", None),
        getattr(select, "KQ_NOTE_EXIT", None),
    )
    if (
        not callable(kqueue_factory)
        or not callable(kevent_factory)
        or not all(isinstance(value, int) for value in constants)
    ):
        return False
    filter_proc, event_add, event_oneshot, note_exit = cast(tuple[int, int, int, int], constants)
    event_queue = cast(_Kqueue, kqueue_factory())
    exit_event = kevent_factory(
        process.pid,
        filter=filter_proc,
        flags=event_add | event_oneshot,
        fflags=note_exit,
    )
    try:
        return bool(event_queue.control([exit_event], 1, _remaining_deadline(deadline)))
    except (OSError, ValueError):
        return False
    finally:
        event_queue.close()


def _spawn_scanner_process(
    argv: Sequence[str],
    *,
    env: Mapping[str, str],
    timeout_seconds: float,
    working_directory: Path,
) -> tuple[subprocess.Popen[bytes], _WindowsJob | None]:
    if os.name == "nt":
        from ..guard.codex_hook_windows_job import spawn_windows_hook_process

        process, job = spawn_windows_hook_process(
            list(argv),
            cwd=working_directory,
            environment=dict(env),
            memory_limit_bytes=_MAX_SCANNER_MEMORY_BYTES,
            active_process_limit=64,
        )
        return process, job
    process = subprocess.Popen(
        _scanner_argv_with_posix_lockdown(argv),
        cwd=working_directory,
        env=dict(env),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        close_fds=True,
        start_new_session=True,
        preexec_fn=(lambda: _apply_resource_limits(timeout_seconds)) if os.name == "posix" else None,
    )
    return process, None


def _scanner_argv_with_posix_lockdown(argv: Sequence[str]) -> list[str]:
    command = list(argv)
    if sys.platform == "darwin":
        sandbox_exec = Path("/usr/bin/sandbox-exec")
        if not sandbox_exec.is_file():
            raise OSError("macOS scanner process sandbox is unavailable")
        return [str(sandbox_exec), "-p", _MACOS_SCANNER_SANDBOX, *command]
    if sys.platform.startswith("linux"):
        return [sys.executable, "-I", "-c", _POSIX_LOCKDOWN_BOOTSTRAP, json.dumps(command)]
    return command


def _exec_posix_scanner_with_lockdown() -> None:
    if len(sys.argv) != 2:
        raise RuntimeError("scanner lockdown bootstrap requires one argv payload")
    payload = json.loads(sys.argv[1])
    if not isinstance(payload, list) or not payload or not all(isinstance(value, str) for value in payload):
        raise RuntimeError("scanner lockdown bootstrap received invalid argv")
    if sys.platform.startswith("linux"):
        _install_linux_process_group_lockdown()
    os.execvpe(payload[0], payload, os.environ)


def _install_linux_process_group_lockdown() -> None:
    instructions = _linux_process_group_lockdown_instructions(platform.machine().lower())
    filter_array = (_SockFilter * len(instructions))(*instructions)
    program = _SockFprog(len(instructions), filter_array)
    libc = ctypes.CDLL(None, use_errno=True)
    prctl = libc.prctl
    prctl.argtypes = (ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong)
    prctl.restype = ctypes.c_int
    if prctl(38, 1, 0, 0, 0) != 0 or prctl(22, 2, ctypes.addressof(program), 0, 0) != 0:
        error_number = ctypes.get_errno()
        raise OSError(error_number, os.strerror(error_number))


def _linux_process_group_lockdown_instructions(machine: str) -> tuple[_SockFilter, ...]:
    architecture_contract = {
        "aarch64": (0xC00000B7, (154, 157), False),
        "arm64": (0xC00000B7, (154, 157), False),
        "x86_64": (0xC000003E, (109, 112), True),
    }.get(machine)
    if architecture_contract is None:
        raise OSError(f"unsupported Linux scanner containment architecture: {machine}")
    audit_architecture, syscall_numbers, reject_x32 = architecture_contract
    bpf_load_syscall = 0x20
    bpf_jump_equal = 0x15
    bpf_jump_bits_set = 0x45
    bpf_return = 0x06
    seccomp_allow = 0x7FFF0000
    seccomp_errno = 0x00050000 | errno.EPERM
    seccomp_kill_process = 0x80000000
    instructions = [
        _SockFilter(bpf_load_syscall, 0, 0, 4),
        _SockFilter(bpf_jump_equal, 1, 0, audit_architecture),
        _SockFilter(bpf_return, 0, 0, seccomp_kill_process),
        _SockFilter(bpf_load_syscall, 0, 0, 0),
    ]
    if reject_x32:
        instructions.extend(
            (
                _SockFilter(bpf_jump_bits_set, 0, 1, 0x40000000),
                _SockFilter(bpf_return, 0, 0, seccomp_kill_process),
            )
        )
    for syscall_number in syscall_numbers:
        instructions.extend(
            (
                _SockFilter(bpf_jump_equal, 0, 1, syscall_number),
                _SockFilter(bpf_return, 0, 0, seccomp_errno),
            )
        )
    instructions.append(_SockFilter(bpf_return, 0, 0, seccomp_allow))
    return tuple(instructions)


def _start_bounded_drain(stream: BinaryIO | None, output: bytearray) -> threading.Thread:
    if stream is None:
        raise RuntimeError("scanner subprocess stream was not captured")

    def drain() -> None:
        try:
            while chunk := stream.read(65_536):
                remaining = MAX_SCANNER_OUTPUT_BYTES - len(output)
                if remaining > 0:
                    output.extend(chunk[:remaining])
        except (OSError, ValueError):
            pass
        finally:
            stream.close()

    thread = threading.Thread(target=drain, daemon=True)
    thread.start()
    return thread


def _finish_bounded_drain(thread: threading.Thread, stream: BinaryIO | None, deadline: float) -> None:
    thread.join(timeout=_remaining_deadline(deadline))
    if thread.is_alive() and stream is not None:
        with contextlib.suppress(OSError, ValueError):
            stream.close()
        thread.join(timeout=0.1)


def _apply_resource_limits(timeout_seconds: float) -> None:
    if _resource is None:
        return
    # Keep the CPU ceiling beyond the wall deadline so the parent consistently
    # classifies deadline exhaustion as a timeout instead of a generic signal exit.
    cpu_seconds = max(1, math.ceil(timeout_seconds) + 1)
    _set_limit(_resource.RLIMIT_CPU, cpu_seconds)
    _set_limit(_resource.RLIMIT_FSIZE, MAX_SCANNER_OUTPUT_BYTES)
    _set_limit(_resource.RLIMIT_NOFILE, 256)
    if hasattr(_resource, "RLIMIT_AS"):
        _set_limit(_resource.RLIMIT_AS, _MAX_SCANNER_MEMORY_BYTES)


def _set_limit(resource_name: int, requested: int) -> None:
    if _resource is None:
        return
    try:
        _soft, hard = _resource.getrlimit(resource_name)
        effective = requested if hard == _resource.RLIM_INFINITY else min(requested, hard)
        _resource.setrlimit(resource_name, (effective, effective))
    except (OSError, ValueError):
        # Some kernels expose a limit constant but reject setting it for a child.
        return


def _terminate_process_group(
    process: subprocess.Popen[bytes],
    *,
    windows_job: _WindowsJob | None = None,
) -> None:
    if os.name == "posix":
        with contextlib.suppress(OSError):
            os.killpg(process.pid, signal.SIGKILL)
        return
    if windows_job is not None:
        with contextlib.suppress(OSError):
            windows_job.terminate()
    with contextlib.suppress(OSError):
        process.kill()


def _close_windows_job(job: _WindowsJob) -> None:
    try:
        job.close()
    except OSError:
        with contextlib.suppress(OSError):
            job.terminate()
        job.close()
