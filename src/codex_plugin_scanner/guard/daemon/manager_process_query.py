"""Bounded child-process queries used by daemon lifecycle inventory.

Collaborators, constants and stdlib modules resolve through ``manager`` at call
time so the manager remains the single patch surface (see
``manager_ephemeral_reap`` for the same late-bound arrangement).
"""

from __future__ import annotations

import subprocess
import threading
from contextlib import suppress
from pathlib import Path
from typing import BinaryIO

from .manager_ephemeral_reap import _ManagerProxy

m = _ManagerProxy()


def _spawn_bounded_process_query(command: list[str]) -> subprocess.Popen[bytes]:
    child_environment = m._process_query_environment(command)
    if m.os.name == "nt":
        return m.subprocess.Popen(
            command,
            stdin=m.subprocess.DEVNULL,
            stdout=m.subprocess.PIPE,
            stderr=m.subprocess.DEVNULL,
            bufsize=0,
            creationflags=m.subprocess.CREATE_NEW_PROCESS_GROUP,
            env=child_environment,
        )
    return m.subprocess.Popen(
        command,
        stdin=m.subprocess.DEVNULL,
        stdout=m.subprocess.PIPE,
        stderr=m.subprocess.DEVNULL,
        bufsize=0,
        start_new_session=True,
        env=child_environment,
    )


def _process_query_environment(command: list[str]) -> dict[str, str]:
    """Return an environment that cannot redirect trusted process-query tools."""

    if m.os.name != "nt":
        return {"LANG": "C", "LC_ALL": "C"}
    if not command:
        return {}
    system_directory = m.ntpath.dirname(m.ntpath.dirname(m.ntpath.dirname(command[0])))
    windows_directory = m.ntpath.dirname(system_directory)
    return {
        "ComSpec": m.ntpath.join(system_directory, "cmd.exe"),
        "PATH": system_directory,
        "SystemRoot": windows_directory,
        "WINDIR": windows_directory,
    }


def _trusted_posix_ps_path() -> str | None:
    """Resolve ``ps`` only from fixed operating-system locations."""

    if m.os.name == "nt":
        return None
    for raw_path in m._GUARD_DAEMON_POSIX_PS_PATHS:
        candidate = Path(raw_path)
        try:
            resolved = candidate.resolve(strict=True)
            metadata = resolved.stat()
        except (OSError, RuntimeError):
            continue
        if m.stat.S_ISREG(metadata.st_mode) and m.os.access(resolved, m.os.X_OK):
            return str(resolved)
    return None


def _linux_proc_process_entries(proc_root: Path = Path("/proc")) -> list[tuple[int, str]] | None:
    """Read a bounded process inventory from Linux procfs without requiring procps."""

    entries: list[tuple[int, str]] = []
    remaining_bytes = m._GUARD_DAEMON_PROCESS_QUERY_OUTPUT_LIMIT_BYTES
    try:
        process_dirs = proc_root.iterdir()
        for process_dir in process_dirs:
            if not process_dir.name.isdigit():
                continue
            pid = int(process_dir.name)
            if pid <= 0:
                continue
            try:
                with (process_dir / "cmdline").open("rb") as stream:
                    raw_command = stream.read(remaining_bytes + 1)
            except FileNotFoundError:
                continue
            except OSError:
                return None
            if len(raw_command) > remaining_bytes:
                return None
            remaining_bytes -= len(raw_command)
            if not raw_command:
                continue
            command = raw_command.rstrip(b"\0").replace(b"\0", b" ").decode("utf-8", errors="replace").strip()
            if command:
                entries.append((pid, command))
    except OSError:
        return None
    return entries


def _terminate_bounded_process_query(process: subprocess.Popen[bytes]) -> None:
    pid = getattr(process, "pid", None)
    wait = getattr(process, "wait", None)
    poll = getattr(process, "poll", None)
    if m.os.name == "nt":
        terminate = getattr(process, "terminate", None)
        if callable(terminate):
            with suppress(OSError):
                terminate()
    elif isinstance(pid, int) and pid > 0:
        with suppress(OSError):
            m.os.killpg(pid, m.signal.SIGTERM)
    if callable(wait):
        with suppress(m.subprocess.TimeoutExpired):
            _ = wait(timeout=m._GUARD_DAEMON_PROCESS_QUERY_TERMINATE_GRACE_SECONDS)
    if callable(poll) and poll() is not None:
        return
    if m.os.name == "nt":
        kill = getattr(process, "kill", None)
        if callable(kill):
            with suppress(OSError):
                kill()
    elif isinstance(pid, int) and pid > 0:
        with suppress(OSError):
            m.os.killpg(pid, m.signal.SIGKILL)
    if callable(wait):
        with suppress(m.subprocess.TimeoutExpired):
            _ = wait(timeout=m._GUARD_DAEMON_PROCESS_QUERY_TERMINATE_GRACE_SECONDS)


def _capture_bounded_process_query_stdout(
    stream: BinaryIO,
    captured: bytearray,
    output_limit_bytes: int,
    overflow: threading.Event,
    errors: list[OSError | ValueError],
) -> None:
    try:
        while True:
            remaining = output_limit_bytes - len(captured)
            chunk = stream.read(min(64 * 1024, remaining + 1))
            if not chunk:
                return
            if len(chunk) > remaining:
                captured.extend(chunk[:remaining])
                overflow.set()
                return
            captured.extend(chunk)
    except (OSError, ValueError) as error:
        errors.append(error)
    finally:
        with suppress(OSError, ValueError):
            stream.close()


def _bounded_process_query_stdout(
    command: list[str],
    *,
    timeout_seconds: float | None = None,
    output_limit_bytes: int | None = None,
) -> str | None:
    """Return bounded child stdout, or ``None`` after failure, timeout, or overflow."""

    timeout_seconds = (
        float(m._GUARD_DAEMON_PROCESS_QUERY_TIMEOUT_SECONDS) if timeout_seconds is None else timeout_seconds
    )
    output_limit_bytes = (
        int(m._GUARD_DAEMON_PROCESS_QUERY_OUTPUT_LIMIT_BYTES) if output_limit_bytes is None else output_limit_bytes
    )
    if timeout_seconds <= 0 or output_limit_bytes < 0:
        return None
    try:
        process = m._spawn_bounded_process_query(command)
    except (OSError, m.subprocess.SubprocessError, ValueError):
        return None
    stdout = getattr(process, "stdout", None)
    if stdout is None:
        m._terminate_bounded_process_query(process)
        return None

    captured = bytearray()
    overflow = m.threading.Event()
    errors: list[OSError | ValueError] = []
    reader = m.threading.Thread(
        target=m._capture_bounded_process_query_stdout,
        args=(stdout, captured, output_limit_bytes, overflow, errors),
        name="guard-daemon-process-query",
        daemon=True,
    )
    timed_out = False
    reader_started = False
    deadline = m.time.monotonic() + timeout_seconds
    try:
        reader.start()
        reader_started = True
        while process.poll() is None:
            remaining = deadline - m.time.monotonic()
            if remaining <= 0:
                timed_out = True
                break
            if overflow.wait(min(m._GUARD_DAEMON_PROCESS_QUERY_MONITOR_INTERVAL_SECONDS, remaining)):
                break
        if process.poll() is not None and reader.is_alive():
            remaining = deadline - m.time.monotonic()
            if remaining <= 0:
                timed_out = True
            else:
                reader.join(timeout=remaining)
                if reader.is_alive() or m.time.monotonic() >= deadline:
                    timed_out = True
    except BaseException:
        m._terminate_bounded_process_query(process)
        raise
    finally:
        if timed_out or overflow.is_set() or process.poll() is None or reader.is_alive():
            m._terminate_bounded_process_query(process)
        if reader_started:
            reader.join(timeout=m._GUARD_DAEMON_PROCESS_QUERY_TERMINATE_GRACE_SECONDS)
            if reader.is_alive():
                with suppress(OSError, ValueError):
                    stdout.close()
                reader.join(timeout=m._GUARD_DAEMON_PROCESS_QUERY_TERMINATE_GRACE_SECONDS)

    if timed_out or overflow.is_set() or errors or reader.is_alive():
        return None
    try:
        returncode = process.wait(timeout=m._GUARD_DAEMON_PROCESS_QUERY_TERMINATE_GRACE_SECONDS)
    except m.subprocess.TimeoutExpired:
        m._terminate_bounded_process_query(process)
        return None
    if returncode != 0:
        return None
    try:
        return bytes(captured).decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return None
