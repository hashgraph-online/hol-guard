"""Isolated, resource-bounded subprocesses for managed Codex hooks."""

from __future__ import annotations

import os
import signal
import stat
import subprocess
import threading
import time
from collections.abc import Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path

from .codex_hook_process_runtime import (
    _HOOK_PROCESS_FINAL_IO_JOIN_TIMEOUT_SECONDS,
    _HOOK_PROCESS_FINAL_REAP_TIMEOUT_SECONDS,
    join_and_cleanup_hook_process,
    start_hook_io,
    wait_for_hook_process,
)
from .codex_hook_windows_job import (
    WindowsHookJob,
    close_windows_hook_job,
    spawn_windows_hook_process,
)

_HOOK_SUBPROCESS_OUTPUT_LIMIT = 1_000_000
_HOOK_ENVIRONMENT_KEYS = frozenset(
    {
        "CODEX_HOME",
        "COMSPEC",
        "HOME",
        "HOL_GUARD_HOOK_FAILURE_KIND",
        "HOL_GUARD_NATIVE",
        "HOL_GUARD_NATIVE_BINARY",
        # Test-only differential and non-production diagnostic markers. They
        # are forwarded solely so an explicitly configured test oracle keeps
        # the same boundary in contained hook processes.
        "HOL_GUARD_TEST_MODE",
        "HOL_GUARD_PYTHON_ORACLE",
        "HOL_GUARD_NATIVE_DIAGNOSTIC",
        "LANG",
        "PATH",
        "PATHEXT",
        "SYSTEMROOT",
        "TEMP",
        "TMP",
        "TMPDIR",
        "USERPROFILE",
        "WINDIR",
    }
)


def _truncate_decoded_output(value: str, limit: int) -> str:
    """Keep decoded output within a byte budget after replacement decoding."""

    encoded = value.encode("utf-8")
    if len(encoded) <= limit:
        return value
    return encoded[: max(0, limit)].decode("utf-8", errors="ignore")


def _decode_combined_output(
    stdout_bytes: bytearray,
    stderr_bytes: bytearray,
    output_limit: int,
) -> tuple[str, str]:
    """Decode both streams while preserving their shared byte bound."""

    remaining = max(0, output_limit)
    stdout = _truncate_decoded_output(bytes(stdout_bytes).decode("utf-8", errors="replace"), remaining)
    remaining = max(0, remaining - len(stdout.encode("utf-8")))
    stderr = _truncate_decoded_output(bytes(stderr_bytes).decode("utf-8", errors="replace"), remaining)
    return stdout, stderr


@dataclass(frozen=True, slots=True)
class BoundedHookProcessResult:
    """One bounded child result without inherited process context."""

    returncode: int | None
    stdout: str
    output_limit_exceeded: bool
    timed_out: bool
    containment_failed: bool = False
    stderr: str = ""


@dataclass(slots=True)
class _QuarantinedHookProcess:
    process: subprocess.Popen[bytes]
    windows_job: WindowsHookJob | None
    io_threads: tuple[threading.Thread, ...]


_HOOK_PROCESS_CONTAINMENT_FAILED = threading.Event()
_HOOK_PROCESS_QUARANTINE_LOCK = threading.Lock()
_HOOK_PROCESS_QUARANTINE: list[_QuarantinedHookProcess] = []


def _retry_quarantined_hook_processes() -> bool:
    with _HOOK_PROCESS_QUARANTINE_LOCK:
        retry_deadline = time.monotonic() + _HOOK_PROCESS_FINAL_IO_JOIN_TIMEOUT_SECONDS
        survivors: list[_QuarantinedHookProcess] = []
        for quarantined in _HOOK_PROCESS_QUARANTINE:
            contained = _kill_hook_process(quarantined.process, quarantined.windows_job)
            remaining = max(0.0, retry_deadline - time.monotonic())
            try:
                _ = quarantined.process.wait(timeout=min(_HOOK_PROCESS_FINAL_REAP_TIMEOUT_SECONDS, remaining))
            except subprocess.TimeoutExpired:
                contained = False
            for thread in quarantined.io_threads:
                _ = thread.join(timeout=max(0.0, retry_deadline - time.monotonic()))
            if any(thread.is_alive() for thread in quarantined.io_threads):
                contained = False
            elif quarantined.windows_job is not None and contained:
                try:
                    close_windows_hook_job(quarantined.windows_job)
                except OSError:
                    contained = False
                else:
                    quarantined.windows_job = None
            if not any(thread.is_alive() for thread in quarantined.io_threads):
                _close_process_streams(quarantined.process)
            contained = (
                contained
                and quarantined.process.poll() is not None
                and all(not thread.is_alive() for thread in quarantined.io_threads)
            )
            if not contained:
                survivors.append(quarantined)
        _HOOK_PROCESS_QUARANTINE[:] = survivors
        if survivors:
            _HOOK_PROCESS_CONTAINMENT_FAILED.set()
            return False
        _HOOK_PROCESS_CONTAINMENT_FAILED.clear()
        return True


def _quarantine_hook_process(
    process: subprocess.Popen[bytes],
    windows_job: WindowsHookJob | None,
    io_threads: Sequence[threading.Thread],
) -> None:
    with _HOOK_PROCESS_QUARANTINE_LOCK:
        if any(quarantined.process is process for quarantined in _HOOK_PROCESS_QUARANTINE):
            _HOOK_PROCESS_CONTAINMENT_FAILED.set()
            return
        _HOOK_PROCESS_QUARANTINE.append(
            _QuarantinedHookProcess(
                process=process,
                windows_job=windows_job,
                io_threads=tuple(io_threads),
            )
        )
        _HOOK_PROCESS_CONTAINMENT_FAILED.set()


def _close_process_streams(process: subprocess.Popen[bytes]) -> None:
    for stream in (
        getattr(process, "stdin", None),
        getattr(process, "stdout", None),
        getattr(process, "stderr", None),
    ):
        if stream is not None:
            with suppress(OSError):
                stream.close()


def isolated_guard_cli_command(
    python_executable: str,
    package_root: Path,
    guard_args: Sequence[str],
) -> tuple[str, ...]:
    """Build the exact isolated fallback contract pinned to one package root."""

    bootstrap = (
        "import sys;"
        f"sys.path.insert(0, {str(package_root.resolve())!r});"
        "from codex_plugin_scanner.cli import main;"
        "raise SystemExit(main(sys.argv[1:]))"
    )
    return (python_executable, "-I", "-c", bootstrap, *guard_args)


def isolated_daemon_start_command(
    python_executable: str,
    package_root: Path,
    guard_home: Path,
    home_dir: Path | None = None,
) -> tuple[str, ...]:
    """Build the exact isolated daemon-start contract.

    ``home_dir`` remains optional for callers using the pre-2.1 signature.
    Managed manifests always bind the authenticated canonical home explicitly.
    """

    resolved_home_dir = Path.home() if home_dir is None else home_dir

    bootstrap = (
        "import os,sys;"
        f"sys.path.insert(0, {str(package_root.resolve())!r});"
        "from pathlib import Path;"
        "from codex_plugin_scanner.guard.daemon import schedule_guard_daemon_recovery;"
        "failure_kind=os.environ.get('HOL_GUARD_HOOK_FAILURE_KIND','transport-failure');"
        "failure_kind=failure_kind if failure_kind in"
        " {'overload','transport-failure','authenticated-control-plane-failure'}"
        " else 'transport-failure';"
        f"schedule_guard_daemon_recovery(Path({str(guard_home)!r}),"
        f"home_dir=Path({str(resolved_home_dir)!r}),failure_kind=failure_kind)"
    )
    return (python_executable, "-I", "-c", bootstrap)


def isolated_hook_environment(environment: Mapping[str, str] | None = None) -> dict[str, str]:
    """Keep only OS, user-home, locale, temp, PATH, Codex, and native-mode state."""

    source = os.environ if environment is None else environment
    return {
        name: value
        for name, value in source.items()
        if name.upper() in _HOOK_ENVIRONMENT_KEYS or name.upper().startswith("LC_")
    }


def private_hook_runtime_cwd(manifest_path: Path) -> Path:
    """Return the authenticated manifest's private Guard-owned directory."""

    parent = manifest_path.parent
    try:
        parent_metadata = parent.lstat()
        resolved = parent.resolve(strict=True)
        resolved_metadata = resolved.lstat()
    except (OSError, RuntimeError) as exc:
        raise ValueError("managed Codex hook runtime directory is unavailable") from exc
    if stat.S_ISLNK(parent_metadata.st_mode) or not stat.S_ISDIR(parent_metadata.st_mode):
        raise ValueError("managed Codex hook runtime directory is not a regular directory")
    if (parent_metadata.st_dev, parent_metadata.st_ino) != (resolved_metadata.st_dev, resolved_metadata.st_ino):
        raise ValueError("managed Codex hook runtime directory changed during validation")
    if os.name != "nt":
        current_uid = os.getuid() if hasattr(os, "getuid") else None
        if current_uid is not None and parent_metadata.st_uid != current_uid:
            raise ValueError("managed Codex hook runtime directory has an unexpected owner")
        if stat.S_IMODE(parent_metadata.st_mode) & 0o077:
            raise ValueError("managed Codex hook runtime directory is not owner-only")
    return resolved


def _spawn_hook_process(
    command: Sequence[str],
    *,
    cwd: Path,
    environment: Mapping[str, str],
    allow_windows_breakaway: bool,
    windows_kill_on_job_close: bool,
    parent_liveness: bool,
) -> tuple[subprocess.Popen[bytes], WindowsHookJob | None, int | None]:
    windows_job: WindowsHookJob | None = None
    liveness_read_fd: int | None = None
    liveness_write_fd: int | None = None
    try:
        if os.name == "nt":
            process, windows_job = spawn_windows_hook_process(
                list(command),
                cwd=cwd,
                environment=dict(environment),
                allow_breakaway=allow_windows_breakaway,
                kill_on_close=windows_kill_on_job_close,
            )
        else:
            child_environment = dict(environment)
            pass_fds: tuple[int, ...] = ()
            if parent_liveness:
                liveness_read_fd, liveness_write_fd = os.pipe()
                os.set_inheritable(liveness_read_fd, True)
                child_environment["HOL_GUARD_PARENT_LIVENESS_FD"] = str(liveness_read_fd)
                pass_fds = (liveness_read_fd,)
            process = subprocess.Popen(
                list(command),
                cwd=cwd,
                env=child_environment,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
                pass_fds=pass_fds,
            )
    except OSError:
        for descriptor in (liveness_read_fd, liveness_write_fd):
            if descriptor is not None:
                os.close(descriptor)
        raise
    if liveness_read_fd is not None:
        os.close(liveness_read_fd)
    return process, windows_job, liveness_write_fd


def run_isolated_hook_process(
    command: Sequence[str],
    *,
    input_text: str,
    cwd: Path,
    environment: Mapping[str, str],
    timeout_seconds: float | None = None,
    output_limit: int = _HOOK_SUBPROCESS_OUTPUT_LIMIT,
    allow_windows_breakaway: bool = False,
    windows_kill_on_job_close: bool = True,
    stop_event: threading.Event | None = None,
    parent_liveness: bool = False,
    deadline_monotonic: float | None = None,
) -> BoundedHookProcessResult:
    """Run one child with bounded input lifetime and combined output bytes.

    ``stop_event`` lets a long-lived reviewed helper terminate through the same
    process-group / Windows Job containment path used for deadlines. Existing
    one-shot callers do not need to supply it.

    When ``deadline_monotonic`` is supplied it is authoritative. The deadline
    is captured before process creation so startup and stream cleanup consume
    the caller's existing budget instead of receiving a new minimum timeout.
    """
    if _HOOK_PROCESS_CONTAINMENT_FAILED.is_set() and not _retry_quarantined_hook_processes():
        return BoundedHookProcessResult(None, "", False, False, containment_failed=True)
    if deadline_monotonic is None:
        if timeout_seconds is None:
            return BoundedHookProcessResult(None, "", False, False)
        deadline = time.monotonic() + max(0.0, timeout_seconds)
    else:
        deadline = deadline_monotonic
    try:
        process, windows_job, liveness_write_fd = _spawn_hook_process(
            command,
            cwd=cwd,
            environment=environment,
            allow_windows_breakaway=allow_windows_breakaway,
            windows_kill_on_job_close=windows_kill_on_job_close,
            parent_liveness=parent_liveness,
        )
    except OSError:
        return BoundedHookProcessResult(None, "", False, False)
    stdout_bytes, stderr_bytes, output_limit_exceeded, output_lock, io_threads = start_hook_io(
        process,
        input_text=input_text,
        output_limit=output_limit,
    )
    returncode, timed_out, containment_confirmed, termination_requested = wait_for_hook_process(
        process,
        windows_job,
        deadline=deadline,
        stop_event=stop_event,
        output_limit_exceeded=output_limit_exceeded,
        terminate=_kill_hook_process,
    )
    windows_job, containment_confirmed, job_cleanup_failed = join_and_cleanup_hook_process(
        process,
        windows_job,
        io_threads,
        containment_confirmed=containment_confirmed,
        termination_requested=termination_requested,
        terminate=_kill_hook_process,
        quarantine=_quarantine_hook_process,
        close_streams=_close_process_streams,
        close_job=close_windows_hook_job,
    )
    if liveness_write_fd is not None:
        os.close(liveness_write_fd)
    with output_lock:
        stdout_decoded, stderr_decoded = _decode_combined_output(stdout_bytes, stderr_bytes, output_limit)
    return BoundedHookProcessResult(
        returncode=None if job_cleanup_failed or not containment_confirmed else returncode,
        stdout=stdout_decoded,
        output_limit_exceeded=output_limit_exceeded.is_set(),
        timed_out=timed_out,
        containment_failed=not containment_confirmed,
        stderr=stderr_decoded,
    )


def _kill_hook_process(process: subprocess.Popen[bytes], windows_job: WindowsHookJob | None) -> bool:
    if windows_job is not None:
        try:
            windows_job.terminate()
            return True
        except OSError:
            pass
    if os.name != "nt":
        return _kill_hook_process_group(process)
    if process.poll() is not None:
        return windows_job is None
    try:
        process.kill()
    except (OSError, ProcessLookupError):
        return False
    return windows_job is None


def _kill_hook_process_group(process: subprocess.Popen[bytes]) -> bool:
    try:
        os.killpg(process.pid, signal.SIGKILL)
        return True
    except (OSError, ProcessLookupError):
        if process.poll() is None:
            with suppress(OSError, ProcessLookupError):
                process.kill()
            return False
        return True


__all__ = [
    "BoundedHookProcessResult",
    "isolated_daemon_start_command",
    "isolated_guard_cli_command",
    "isolated_hook_environment",
    "private_hook_runtime_cwd",
    "run_isolated_hook_process",
]
