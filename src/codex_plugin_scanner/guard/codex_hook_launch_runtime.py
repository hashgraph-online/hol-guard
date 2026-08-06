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
from typing import BinaryIO

from .codex_hook_windows_job import (
    WindowsHookJob,
    close_windows_hook_job,
    spawn_windows_hook_process,
)

_HOOK_SUBPROCESS_OUTPUT_LIMIT = 1_000_000
_HOOK_PROCESS_REAP_TIMEOUT_SECONDS = 0.2
_HOOK_PROCESS_FINAL_REAP_TIMEOUT_SECONDS = 0.1
_HOOK_PROCESS_IO_THREAD_JOIN_TIMEOUT_SECONDS = 0.05
_HOOK_PROCESS_FINAL_IO_JOIN_TIMEOUT_SECONDS = 1.0
_HOOK_ENVIRONMENT_KEYS = frozenset(
    {
        "CODEX_HOME",
        "COMSPEC",
        "HOME",
        "HOL_GUARD_HOOK_FAILURE_KIND",
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


@dataclass(frozen=True, slots=True)
class BoundedHookProcessResult:
    """One bounded child result without inherited process context."""

    returncode: int | None
    stdout: str
    output_limit_exceeded: bool
    timed_out: bool
    containment_failed: bool = False


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
            if quarantined.windows_job is not None:
                try:
                    close_windows_hook_job(quarantined.windows_job)
                except OSError:
                    contained = False
                else:
                    quarantined.windows_job = None
            for thread in quarantined.io_threads:
                _ = thread.join(timeout=max(0.0, retry_deadline - time.monotonic()))
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
    """Keep only OS, user-home, locale, temp, PATH, and Codex state."""

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


def run_isolated_hook_process(
    command: Sequence[str],
    *,
    input_text: str,
    cwd: Path,
    environment: Mapping[str, str],
    timeout_seconds: float,
    output_limit: int = _HOOK_SUBPROCESS_OUTPUT_LIMIT,
    allow_windows_breakaway: bool = False,
) -> BoundedHookProcessResult:
    """Run one child with bounded input lifetime and combined output bytes."""

    if _HOOK_PROCESS_CONTAINMENT_FAILED.is_set() and not _retry_quarantined_hook_processes():
        return BoundedHookProcessResult(None, "", False, False, containment_failed=True)
    windows_job: WindowsHookJob | None = None
    try:
        if os.name == "nt":
            process, windows_job = spawn_windows_hook_process(
                list(command),
                cwd=cwd,
                environment=dict(environment),
                allow_breakaway=allow_windows_breakaway,
            )
        else:
            process = subprocess.Popen(
                list(command),
                cwd=cwd,
                env=dict(environment),
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
            )
    except OSError:
        return BoundedHookProcessResult(None, "", False, False)

    stdout_bytes = bytearray()
    output_bytes = 0
    output_lock = threading.Lock()
    output_limit_exceeded = threading.Event()

    def drain(stream: BinaryIO, *, capture: bool) -> None:
        nonlocal output_bytes
        while chunk := stream.read(64 * 1024):
            with output_lock:
                remaining = max(0, output_limit - output_bytes)
                accepted = chunk[:remaining]
                output_bytes += len(chunk)
                if capture and accepted:
                    stdout_bytes.extend(accepted)
                if output_bytes > output_limit:
                    output_limit_exceeded.set()

    def write_input() -> None:
        if process.stdin is None:
            return
        try:
            process.stdin.write(input_text.encode("utf-8"))
            process.stdin.flush()
        except (BrokenPipeError, OSError):
            pass
        finally:
            process.stdin.close()

    readers = [
        threading.Thread(target=drain, args=(process.stdout,), kwargs={"capture": True}, daemon=True),
        threading.Thread(target=drain, args=(process.stderr,), kwargs={"capture": False}, daemon=True),
    ]
    writer = threading.Thread(target=write_input, daemon=True)
    for thread in readers:
        thread.start()
    writer.start()

    deadline = time.monotonic() + max(0.0, timeout_seconds)
    timed_out = False
    containment_confirmed = True
    while process.poll() is None:
        if output_limit_exceeded.is_set():
            containment_confirmed = _kill_hook_process(process, windows_job)
            break
        if time.monotonic() >= deadline:
            timed_out = True
            containment_confirmed = _kill_hook_process(process, windows_job)
            break
        time.sleep(0.01)
    try:
        returncode = process.wait(timeout=_HOOK_PROCESS_REAP_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        containment_confirmed = _kill_hook_process(process, windows_job) and containment_confirmed
        try:
            returncode = process.wait(timeout=_HOOK_PROCESS_FINAL_REAP_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired:
            containment_confirmed = False
            returncode = None
    job_cleanup_failed = False
    if windows_job is not None:
        try:
            close_windows_hook_job(windows_job)
        except OSError:
            job_cleanup_failed = True
            containment_confirmed = False
            _ = _kill_hook_process(process, windows_job)
        else:
            windows_job = None
    io_threads = [writer, *readers]
    io_join_deadline = time.monotonic() + _HOOK_PROCESS_IO_THREAD_JOIN_TIMEOUT_SECONDS
    for thread in io_threads:
        thread.join(timeout=max(0.0, io_join_deadline - time.monotonic()))
    if any(thread.is_alive() for thread in io_threads):
        containment_confirmed = _kill_hook_process(process, windows_job) and containment_confirmed
        final_io_join_deadline = time.monotonic() + _HOOK_PROCESS_FINAL_IO_JOIN_TIMEOUT_SECONDS
        for thread in io_threads:
            thread.join(timeout=max(0.0, final_io_join_deadline - time.monotonic()))
        if any(thread.is_alive() for thread in io_threads):
            containment_confirmed = False
    if not containment_confirmed:
        _quarantine_hook_process(process, windows_job, io_threads)
    with output_lock:
        stdout_decoded = stdout_bytes.decode("utf-8", errors="replace")
    return BoundedHookProcessResult(
        returncode=None if job_cleanup_failed or not containment_confirmed else returncode,
        stdout=stdout_decoded,
        output_limit_exceeded=output_limit_exceeded.is_set(),
        timed_out=timed_out,
        containment_failed=not containment_confirmed,
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
