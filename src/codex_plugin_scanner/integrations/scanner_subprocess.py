"""Bounded subprocess execution for optional third-party scanners."""

from __future__ import annotations

import contextlib
import math
import os
import signal
import subprocess
import tempfile
import threading
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Protocol, cast

if os.name == "posix":
    import resource as _resource
else:
    _resource = None

MAX_SCANNER_OUTPUT_BYTES = 8 * 1024 * 1024
_MAX_SCANNER_MEMORY_BYTES = 4 * 1024 * 1024 * 1024
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
            else:
                _terminate_process_group(process)
            _finish_bounded_drain(stdout_thread, cast(BinaryIO | None, process.stdout), deadline)
            _finish_bounded_drain(stderr_thread, cast(BinaryIO | None, process.stderr), deadline)
        stdout = bytes(stdout_buffer).decode("utf-8", errors="replace")
        stderr = bytes(stderr_buffer).decode("utf-8", errors="replace")
    return ScannerProcessResult(process.returncode, stdout, stderr, timed_out)


def _remaining_deadline(deadline: float) -> float:
    return max(deadline - time.monotonic(), 0.001)


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
        list(argv),
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
    cpu_seconds = max(1, math.ceil(timeout_seconds))
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
