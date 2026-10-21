"""Bounded subprocess runner for the Guard interpreter probe."""

from __future__ import annotations

import contextlib
import math
import os
import selectors
import signal
import subprocess
import threading
import time
from _thread import LockType
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO, Final

from ..codex_hook_windows_job import WindowsHookJob, spawn_windows_hook_process

_PROBE_TIMEOUT_SECONDS: Final = 15
_PROBE_OUTPUT_LIMIT_BYTES: Final = 64 * 1024
_PROBE_REAP_TIMEOUT_SECONDS: Final = 1.0


@dataclass(frozen=True, slots=True)
class ProbeResult:
    returncode: int
    stdout: bytes
    stderr: bytes
    timed_out: bool
    output_overflow: bool
    capture_incomplete: bool = False


@dataclass(slots=True)
class _ProbeWindowsJob:
    job: WindowsHookJob
    lock: LockType = field(default_factory=threading.Lock)

    def terminate(self) -> None:
        with self.lock:
            self.job.terminate()

    def close(self) -> None:
        with self.lock:
            self.job.close()


@dataclass(slots=True)
class _OutputBudget:
    total_limit: int
    stream_limit: int
    retained: int = 0
    lock: LockType = field(default_factory=threading.Lock)

    def retain(self, chunk: bytes, stream_size: int) -> tuple[bytes, bool]:
        with self.lock:
            available = min(self.total_limit - self.retained, self.stream_limit - stream_size)
            kept = chunk[: max(0, available)]
            self.retained += len(kept)
            return kept, len(kept) != len(chunk)


def _run_posix_probe(
    command: list[str], *, cwd: Path, env: dict[str, str], timeout: float, budget: _OutputBudget
) -> ProbeResult:
    process = subprocess.Popen(
        command,
        cwd=cwd,
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
        shell=False,
    )
    assert process.stdout is not None
    assert process.stderr is not None
    deadline = time.monotonic() + timeout
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    timed_out = output_overflow = capture_incomplete = False
    stopped = False

    def stop_owned_group() -> None:
        nonlocal stopped, capture_incomplete
        if stopped:
            return
        stopped = True
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except OSError:
            capture_incomplete = True
            with contextlib.suppress(OSError):
                process.kill()

    try:
        with selectors.DefaultSelector() as selector:
            for name, stream in (("stdout", process.stdout), ("stderr", process.stderr)):
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ, name)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    timed_out = True
                    break
                for key, _ in selector.select(remaining):
                    try:
                        chunk = os.read(key.fd, 4096)
                    except BlockingIOError:
                        continue
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    buffer = buffers[key.data]
                    kept, overflow = budget.retain(chunk, len(buffer))
                    buffer.extend(kept)
                    if overflow:
                        output_overflow = True
                        break
                if output_overflow:
                    break
        if timed_out or output_overflow:
            stop_owned_group()
        try:
            process.wait(timeout=max(0, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            timed_out = True
            stop_owned_group()
    except (OSError, ValueError):
        capture_incomplete = True
    finally:
        if process.returncode is None:
            stop_owned_group()
            try:
                process.wait(timeout=_PROBE_REAP_TIMEOUT_SECONDS)
            except subprocess.TimeoutExpired:
                capture_incomplete = True
        process.stdout.close()
        process.stderr.close()
    return ProbeResult(
        returncode=process.returncode if process.returncode is not None else -1,
        stdout=bytes(buffers["stdout"]),
        stderr=bytes(buffers["stderr"]),
        timed_out=timed_out,
        output_overflow=output_overflow,
        capture_incomplete=capture_incomplete,
    )


def _stop_threaded_probe(
    process: subprocess.Popen[bytes], job: _ProbeWindowsJob | None, capture_error: threading.Event
) -> None:
    try:
        if job is not None:
            job.terminate()
        else:
            process.kill()
    except OSError:
        capture_error.set()
        if job is not None:
            with contextlib.suppress(OSError):
                job.close()
        with contextlib.suppress(OSError):
            process.kill()


def _read_bounded_stream(
    stream: BinaryIO,
    chunks: list[bytes],
    overflow: threading.Event,
    process: subprocess.Popen[bytes],
    budget: _OutputBudget,
    capture_error: threading.Event,
    job: _ProbeWindowsJob | None,
) -> None:
    total = 0
    while True:
        try:
            chunk = stream.read(4096)
        except (OSError, ValueError):
            capture_error.set()
            return
        if not chunk:
            return
        kept, exceeded = budget.retain(chunk, total)
        chunks.append(kept)
        total += len(kept)
        if exceeded:
            overflow.set()
            _stop_threaded_probe(process, job, capture_error)
            return


def run_probe(
    command: list[str],
    *,
    cwd: Path,
    env: dict[str, str],
    timeout_seconds: float | None = None,
    output_limit_bytes: int | None = None,
) -> ProbeResult:
    """Run a probe with no stdin and strictly bounded output and duration.

    An explicit output limit is shared by stdout and stderr. Either stream may
    use the full shared budget. Defaults retain 64 KiB for each stream.
    """

    timeout = float(_PROBE_TIMEOUT_SECONDS) if timeout_seconds is None else timeout_seconds
    if (
        isinstance(timeout, bool)
        or not isinstance(timeout, (int, float))
        or not math.isfinite(timeout)
        or not 0 < timeout <= 3600
    ):
        raise ValueError("invalid probe timeout")
    output_limit = 2 * _PROBE_OUTPUT_LIMIT_BYTES if output_limit_bytes is None else output_limit_bytes
    if (
        isinstance(output_limit, bool)
        or not isinstance(output_limit, int)
        or not 0 < output_limit <= 2 * _PROBE_OUTPUT_LIMIT_BYTES
    ):
        raise ValueError("invalid probe output limit")
    stream_limit = _PROBE_OUTPUT_LIMIT_BYTES if output_limit_bytes is None else output_limit
    budget = _OutputBudget(output_limit, stream_limit)
    job: _ProbeWindowsJob | None = None
    try:
        if os.name == "posix":
            return _run_posix_probe(command, cwd=cwd, env=env, timeout=timeout, budget=budget)
        if os.name == "nt":
            process, windows_job = spawn_windows_hook_process(command, cwd=cwd, environment=env)
            job = _ProbeWindowsJob(windows_job)
            assert process.stdin is not None
            try:
                process.stdin.close()
            except (OSError, ValueError):
                try:
                    job.close()
                except OSError:
                    _stop_threaded_probe(process, job, threading.Event())
                with contextlib.suppress(OSError, subprocess.TimeoutExpired):
                    process.wait(timeout=_PROBE_REAP_TIMEOUT_SECONDS)
                raise
        else:
            process = subprocess.Popen(
                command,
                cwd=cwd,
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
    except (OSError, ValueError) as error:
        raise RuntimeError("guard_hook_python_probe_execution_failed") from error
    assert process.stdout is not None
    assert process.stderr is not None
    stdout_chunks: list[bytes] = []
    stderr_chunks: list[bytes] = []
    overflow = threading.Event()
    capture_error = threading.Event()
    readers = (
        threading.Thread(
            target=_read_bounded_stream,
            args=(process.stdout, stdout_chunks, overflow, process, budget, capture_error, job),
            daemon=True,
        ),
        threading.Thread(
            target=_read_bounded_stream,
            args=(process.stderr, stderr_chunks, overflow, process, budget, capture_error, job),
            daemon=True,
        ),
    )
    deadline = time.monotonic() + timeout
    timed_out = capture_incomplete = False
    try:
        for reader in readers:
            reader.start()
        try:
            _ = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            _stop_threaded_probe(process, job, capture_error)
            try:
                _ = process.wait(timeout=_PROBE_REAP_TIMEOUT_SECONDS)
            except subprocess.TimeoutExpired:
                capture_incomplete = True
    finally:
        if job is not None:
            try:
                job.close()
            except OSError:
                capture_error.set()
                _stop_threaded_probe(process, job, capture_error)
    for reader in readers:
        reader.join(timeout=max(0, deadline - time.monotonic()))
    capture_incomplete = capture_incomplete or capture_error.is_set() or any(reader.is_alive() for reader in readers)
    if any(reader.is_alive() for reader in readers):
        grace_deadline = time.monotonic() + _PROBE_REAP_TIMEOUT_SECONDS
        for reader in readers:
            reader.join(timeout=max(0, grace_deadline - time.monotonic()))
    for reader, stream in zip(readers, (process.stdout, process.stderr), strict=True):
        if not reader.is_alive():
            try:
                stream.close()
            except OSError:
                capture_incomplete = True
    return ProbeResult(
        returncode=process.returncode if process.returncode is not None else -1,
        stdout=b"".join(stdout_chunks),
        stderr=b"".join(stderr_chunks),
        timed_out=timed_out,
        output_overflow=overflow.is_set(),
        capture_incomplete=capture_incomplete,
    )


__all__ = ["ProbeResult", "run_probe"]
