"""Bounded process identity proof for a locally waiting hook."""

from __future__ import annotations

import os
import stat
import subprocess
from collections.abc import Mapping
from pathlib import Path
from typing import cast

from .windows_paths import windows_process_creation_time

_TRUSTED_POSIX_PS_PATHS = ("/bin/ps", "/usr/bin/ps")
CODEX_BROWSER_WAIT_PROCESS_KEY = "guard_codex_browser_wait_process"


def current_process_identity() -> dict[str, object] | None:
    """Capture an opaque identity that distinguishes PID reuse."""

    pid = os.getpid()
    start_token = _process_start_token(pid)
    if start_token is None:
        return None
    return {"pid": pid, "startToken": start_token}


def process_identity_matches(value: object) -> bool:
    """Prove that the captured process is still the same live process."""

    if not isinstance(value, Mapping):
        return False
    raw = cast(Mapping[object, object], value)
    if set(raw) != {"pid", "startToken"}:
        return False
    pid = raw.get("pid")
    start_token = raw.get("startToken")
    if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0:
        return False
    if not isinstance(start_token, str) or not start_token:
        return False
    return _process_start_token(pid) == start_token


def _process_start_token(pid: int) -> str | None:
    if os.name == "nt":
        created_at = windows_process_creation_time(pid)
        return f"windows:{created_at}" if created_at is not None else None
    proc_stat = _linux_proc_stat(pid)
    if proc_stat is not None:
        return f"linux:{proc_stat}"
    ps_path = _trusted_posix_ps_path()
    if ps_path is None:
        return None
    try:
        result = subprocess.run(
            [ps_path, "-p", str(pid), "-o", "lstart="],
            check=False,
            capture_output=True,
            env={"LANG": "C", "LC_ALL": "C"},
            text=True,
            timeout=0.5,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    started_at = result.stdout.strip()
    return f"posix:{started_at}" if result.returncode == 0 and started_at else None


def _trusted_posix_ps_path() -> str | None:
    for raw_path in _TRUSTED_POSIX_PS_PATHS:
        candidate = Path(raw_path)
        try:
            resolved = candidate.resolve(strict=True)
            metadata = resolved.stat()
        except (OSError, RuntimeError):
            continue
        if stat.S_ISREG(metadata.st_mode) and os.access(resolved, os.X_OK):
            return str(resolved)
    return None


def _linux_proc_stat(pid: int) -> str | None:
    try:
        raw = os.path.join("/proc", str(pid), "stat")
        with open(raw, encoding="ascii") as handle:
            value = handle.read(4096)
    except (OSError, UnicodeError):
        return None
    _, separator, suffix = value.rpartition(")")
    if not separator:
        return None
    fields = suffix.split()
    # The suffix starts at proc field 3; field 22 is the process start tick.
    return fields[19] if len(fields) > 19 and fields[19].isdigit() else None


__all__ = ["CODEX_BROWSER_WAIT_PROCESS_KEY", "current_process_identity", "process_identity_matches"]
