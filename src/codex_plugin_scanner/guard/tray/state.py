"""Tray state persistence: locator file and registration management.

The locator file is the single source of truth for "is a tray running,
where, and since when". It lives under ``<guard_home>/tray/locator.json``
and is written atomically. The schema is versioned (``LOCATOR_SCHEMA_VERSION``);
unknown future versions are rejected, never silently upgraded.

Security contract:
    - Locator payloads never contain auth tokens, URL fragments, or
      secrets. Only process identity (pid, start fingerprint, executable,
      guard_home, backend, registration generation) is persisted.
    - File permissions are 0o600 on POSIX; the file is only ever read
      by the owning user.
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
import tempfile
from datetime import datetime, timedelta
from pathlib import Path

from .contracts import (
    CRASH_LOOP_WINDOW_SECONDS,
    LOCATOR_SCHEMA_VERSION,
    MAX_CRASH_RETRIES,
    TrayBackend,
    TrayLocator,
    utcnow,
)

logger = logging.getLogger(__name__)

LOCATOR_FILENAME = "locator.json"
LOCATOR_DIRNAME = "tray"


def locator_path(guard_home: Path) -> Path:
    """Return the canonical locator file path for a Guard home."""
    return guard_home / LOCATOR_DIRNAME / LOCATOR_FILENAME


def ensure_locator_dir(guard_home: Path) -> Path:
    """Create the locator directory if missing. Returns the directory path."""
    directory = guard_home / LOCATOR_DIRNAME
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def write_locator(guard_home: Path, locator: TrayLocator) -> None:
    """Write the locator atomically with 0o600 permissions on POSIX.

    Uses a temp file + rename for atomicity. On POSIX, the file is
    created with mode 0o600 so only the owning user can read it.
    """
    directory = ensure_locator_dir(guard_home)
    target = directory / LOCATOR_FILENAME
    payload = locator.to_payload()

    fd, tmp_path = tempfile.mkstemp(
        prefix=f".{LOCATOR_FILENAME}.",
        suffix=".tmp",
        dir=str(directory),
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(payload, f, sort_keys=True, indent=2)
            f.write("\n")
        os.chmod(tmp_path, 0o600)
        os.replace(tmp_path, target)
    except Exception:
        with contextlib.suppress(OSError):
            os.unlink(tmp_path)
        raise


def read_locator(guard_home: Path) -> TrayLocator | None:
    """Read and validate the locator file.

    Returns None if the file does not exist. Raises ValueError if the
    file is malformed or has an unsupported schema version. Never
    returns a locator with an unknown backend — those are coerced to
    ``TrayBackend.NONE``.
    """
    path = locator_path(guard_home)
    if not path.is_file():
        return None
    try:
        raw = path.read_text(encoding="utf-8")
        payload = json.loads(raw)
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"locator file is not valid JSON: {error}") from error

    if not isinstance(payload, dict):
        raise ValueError("locator payload is not an object")

    return TrayLocator.from_payload(payload)


def remove_locator(guard_home: Path) -> bool:
    """Remove the locator file. Returns True if removed, False if absent."""
    path = locator_path(guard_home)
    try:
        path.unlink()
        return True
    except FileNotFoundError:
        return False


def is_process_alive(pid: int) -> bool:
    """Return True if a process with the given PID is currently running.

    Uses ``os.kill(pid, 0)`` on POSIX and ``tasklist`` on Windows.
    Never raises — returns False on any error.
    """
    if pid <= 0:
        return False
    try:
        if os.name == "nt":
            import subprocess

            result = subprocess.run(
                ["tasklist", "/FI", f"PID eq {pid}", "/NH", "/FO", "CSV"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            # ``tasklist /FI "PID eq {pid}"`` already filters to the exact
            # PID, but ``str(pid) in result.stdout`` is a substring test that
            # would false-positive for PID 123 matching output for PID 1234.
            # tasklist /FO CSV /NH emits rows as "image","PID","session",...
            # so the PID is at field index 1. When no match, tasklist emits
            # ``INFO: No tasks are running...`` (single-field row, no PID).
            import csv
            import io

            reader = csv.reader(io.StringIO(result.stdout))
            for row in reader:
                if len(row) < 2:
                    continue
                if row[1].strip().strip('"') == str(pid):
                    return True
            return False
        os.kill(pid, 0)
        return True
    except (ProcessLookupError, PermissionError, OSError):
        return False
    except Exception:  # pragma: no cover - defensive
        return False


def is_process_owned(
    pid: int,
    *,
    expected_executable: str | None = None,
    expected_guard_home: str | None = None,
) -> bool:
    """Return True if the PID is alive and (optionally) matches expected fields.

    On macOS/Linux, reads ``/proc/<pid>/cmdline`` (Linux) or uses
    ``ps -p <pid> -o command=`` (macOS/BSD). On Windows, uses
    ``wmic process where ProcessId=<pid> get CommandLine``.
    """
    if not is_process_alive(pid):
        return False
    if expected_executable is None and expected_guard_home is None:
        return True
    try:
        cmdline = _read_process_command(pid)
    except Exception:
        return False
    if cmdline is None:
        return False
    if expected_executable and expected_executable not in cmdline:
        return False
    return not (expected_guard_home and expected_guard_home not in cmdline)

def _read_process_command(pid: int) -> str | None:
    """Read the command line for a PID. Returns None on failure.

    On Windows, prefers PowerShell ``Get-CimInstance`` over the deprecated
    ``wmic`` (removed from Windows 11 by default). Falls back to ``wmic``
    only if PowerShell is unavailable.
    """
    if os.name == "nt":
        import subprocess

        # Preferred: PowerShell Get-CimInstance (wmic is deprecated on Win11)
        ps_cmd = (
            f'Get-CimInstance Win32_Process -Filter "ProcessId={pid}" '
            "| Select-Object -ExpandProperty CommandLine"
        )
        try:
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps_cmd],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            if result.returncode == 0 and result.stdout.strip():
                return result.stdout.strip()
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        # Fallback: wmic (pre-Windows 11 / optional feature)
        try:
            result = subprocess.run(
                ["wmic", "process", "where", f"ProcessId={pid}", "get", "CommandLine", "/value"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return None
        for line in result.stdout.splitlines():
            if line.startswith("CommandLine="):
                return line.split("=", 1)[1]
        return None
    if os.name == "posix":
        import subprocess

        result = subprocess.run(
            ["ps", "-p", str(pid), "-o", "command="],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        return result.stdout.strip() or None
    return None


def process_start_fingerprint(pid: int) -> str | None:
    """Return a stable fingerprint for a running process.

    On Linux, uses ``/proc/<pid>/stat`` start time (jiffies since boot).
    On macOS/BSD, uses process start time from ``ps -p <pid> -o lstart=``.
    On Windows, prefers PowerShell ``Get-Process`` StartTime over the
    deprecated ``wmic`` (removed from Windows 11 by default), with a
    ``wmic`` fallback for older systems.
    Returns None if the process is not alive or the fingerprint cannot
    be read.
    """
    if not is_process_alive(pid):
        return None
    try:
        if os.name == "posix":
            import subprocess

            result = subprocess.run(
                ["ps", "-p", str(pid), "-o", "lstart="],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            return result.stdout.strip() or None
        if os.name == "nt":
            import subprocess

            # Preferred: PowerShell Get-Process StartTime (wmic deprecated on Win11)
            ps_cmd = (
                f"(Get-Process -Id {pid} -ErrorAction SilentlyContinue).StartTime.ToString('o')"
            )
            try:
                result = subprocess.run(
                    ["powershell", "-NoProfile", "-Command", ps_cmd],
                    capture_output=True,
                    text=True,
                    timeout=5,
                    check=False,
                )
                if result.returncode == 0 and result.stdout.strip():
                    return result.stdout.strip()
            except (FileNotFoundError, subprocess.TimeoutExpired):
                pass

            # Fallback: wmic CreationDate
            try:
                result = subprocess.run(
                    ["wmic", "process", "where", f"ProcessId={pid}", "get", "CreationDate", "/value"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                    check=False,
                )
            except (FileNotFoundError, subprocess.TimeoutExpired):
                return None
            for line in result.stdout.splitlines():
                if line.startswith("CreationDate="):
                    return line.split("=", 1)[1]
        return None
    except Exception:
        return None


def locator_is_stale(
    locator: TrayLocator,
    *,
    now: datetime | None = None,
) -> bool:
    """Return True if the locator points to a dead or reused process.

    A locator is stale if:
    - The PID is not alive, OR
    - The process start fingerprint (OS-level creation time) has changed,
      which indicates the original process exited and the PID was recycled.

    Note: this does NOT compare command line, executable, or backend —
    those are checked separately via ``TrayProcessIdentity.matches()`` when
    a strict kill-decision is needed. Fingerprint alone is sufficient to
    detect PID reuse and is the only check applied by ``stop_tray``.
    """
    if locator.pid <= 0:
        return True
    if not is_process_alive(locator.pid):
        return True
    current_fingerprint = process_start_fingerprint(locator.pid)
    if current_fingerprint is None:
        return True
    return bool(locator.process_start_fingerprint and current_fingerprint != locator.process_start_fingerprint)


def record_crash(guard_home: Path) -> int:
    """Increment the crash counter in the locator. Returns the new count.

    If the locator is missing or malformed, starts a fresh crash count
    at 1. Does not remove the locator — the lifecycle manager decides
    whether to repair or give up based on ``MAX_CRASH_RETRIES``.
    """
    try:
        locator = read_locator(guard_home)
    except (ValueError, OSError):
        locator = None

    if locator is None:
        # Write a minimal locator with crash_count=1
        new_locator = TrayLocator(
            schema_version=LOCATOR_SCHEMA_VERSION,
            package_version="",
            pid=0,
            process_start_fingerprint="",
            executable="",
            command="",
            guard_home=str(guard_home),
            backend=TrayBackend.NONE,
            registration_generation=0,
            last_ready=None,
            crash_count=1,
            last_crash=utcnow(),
        )
        write_locator(guard_home, new_locator)
        return 1

    new_count = (locator.crash_count or 0) + 1
    updated = TrayLocator(
        schema_version=locator.schema_version,
        package_version=locator.package_version,
        pid=locator.pid,
        process_start_fingerprint=locator.process_start_fingerprint,
        executable=locator.executable,
        command=locator.command,
        guard_home=locator.guard_home,
        backend=locator.backend,
        registration_generation=locator.registration_generation,
        last_ready=locator.last_ready,
        crash_count=new_count,
        last_crash=utcnow(),
    )
    write_locator(guard_home, updated)
    return new_count


def crash_loop_detected(guard_home: Path) -> bool:
    """Return True if the crash count exceeds ``MAX_CRASH_RETRIES`` within the
    crash-loop window.

    A crash counts toward the loop only if it occurred within the last
    ``CRASH_LOOP_WINDOW_SECONDS``. Crashes older than the window are
    considered stale and do not trigger loop detection — this prevents a
    long-lived tray that crashed once weeks ago from being permanently
    blocked from starting.
    """
    try:
        locator = read_locator(guard_home)
    except (ValueError, OSError):
        return False
    if locator is None:
        return False
    if (locator.crash_count or 0) < MAX_CRASH_RETRIES:
        return False
    # Honor the time window: if the most recent crash is older than the
    # window, the loop is stale and start should be allowed.
    if locator.last_crash is not None:
        now = utcnow()
        if now - locator.last_crash > timedelta(seconds=CRASH_LOOP_WINDOW_SECONDS):
            return False
    return True


def reset_crash_count(guard_home: Path) -> None:
    """Reset the crash counter to 0 after a successful start."""
    try:
        locator = read_locator(guard_home)
    except (ValueError, OSError):
        return
    if locator is None:
        return
    if locator.crash_count == 0 and locator.last_crash is None:
        return
    updated = TrayLocator(
        schema_version=locator.schema_version,
        package_version=locator.package_version,
        pid=locator.pid,
        process_start_fingerprint=locator.process_start_fingerprint,
        executable=locator.executable,
        command=locator.command,
        guard_home=locator.guard_home,
        backend=locator.backend,
        registration_generation=locator.registration_generation,
        last_ready=locator.last_ready,
        crash_count=0,
        last_crash=None,
    )
    write_locator(guard_home, updated)


def build_locator_for_current_process(
    *,
    guard_home: Path,
    package_version: str,
    backend: TrayBackend,
    registration_generation: int = 1,
) -> TrayLocator:
    """Build a locator for the currently running tray process."""
    pid = os.getpid()
    fingerprint = process_start_fingerprint(pid) or ""
    return TrayLocator(
        schema_version=LOCATOR_SCHEMA_VERSION,
        package_version=package_version,
        pid=pid,
        process_start_fingerprint=fingerprint,
        executable=sys_executable(),
        command=f"{sys_executable()} -m codex_plugin_scanner.guard.tray.runtime --guard-home {guard_home}",
        guard_home=str(guard_home),
        backend=backend,
        registration_generation=registration_generation,
        last_ready=utcnow(),
        crash_count=0,
        last_crash=None,
    )


def sys_executable() -> str:
    """Return sys.executable, cached for testability."""
    import sys

    return sys.executable
