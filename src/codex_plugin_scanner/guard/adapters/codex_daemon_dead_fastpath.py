"""Fail fast when the Guard daemon is provably dead and could not be started.

Every Codex hook launch normally tries to start a missing daemon and then runs
a local fallback, which can burn the whole hook timeout. If a previous launch
already tried and failed, repeating that on every hook turns one outage into a
stream of 30-second stalls. This module lets later launches skip straight to a
clear denial that names the fix (`hol-guard repair`).

Fail-closed behavior is unchanged: the caller still denies PreToolUse and
PermissionRequest; only the waiting is removed. The shortcut applies only when
all of these hold, so a slow or busy daemon never triggers it:

* the daemon state file is missing, is the empty tombstone a failed restart
  leaves behind, or names a pid that no longer exists;
* a launch recorded a failed start within the last ``FAILED_START_WINDOW_SECONDS``.

Stdlib only; every error means "not provably dead" and the normal flow runs.
"""

from __future__ import annotations

import json
import os
import time
from contextlib import suppress
from pathlib import Path

FAILED_START_WINDOW_SECONDS = 120.0
FAILED_START_MARKER = "daemon-start-failed.json"
DEAD_DAEMON_REASON_CODE = "daemon_dead_repair_needed"


def _marker_path(state_path: str | Path) -> Path:
    return Path(state_path).parent / FAILED_START_MARKER


def _state_pid(state_path: Path) -> tuple[bool, int | None]:
    """Return ``(readable, pid)``.

    ``readable`` is False for unparseable state and for objects that are neither
    a live-style record with a pid nor the empty tombstone, so unknown shapes are
    never taken as proof that the daemon is gone.
    """

    try:
        payload = json.loads(state_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False, None
    if not isinstance(payload, dict):
        return False, None
    if isinstance(payload.get("state"), dict):
        payload = payload["state"]
    pid = payload.get("pid")
    if isinstance(pid, int) and not isinstance(pid, bool) and pid > 0:
        return True, pid
    return not payload, None


def daemon_provably_dead(state_path: str | Path) -> bool:
    """True when no daemon state exists, it is a pid-less tombstone, or its pid is gone."""

    if os.name == "nt":
        return False
    path = Path(state_path)
    if not path.exists():
        return True
    readable, pid = _state_pid(path)
    if not readable:
        return False
    if pid is None:
        # ``clear_guard_daemon_state`` rewrites a failed restart to ``{}``.
        return True
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return True
    except OSError:
        return False
    return False


def recent_start_failure(state_path: str | Path, *, now: float | None = None) -> bool:
    try:
        modified = _marker_path(state_path).stat().st_mtime
    except OSError:
        return False
    current = time.time() if now is None else now
    return 0.0 <= current - modified < FAILED_START_WINDOW_SECONDS


def should_fail_fast(state_path: str | Path, *, now: float | None = None) -> bool:
    return recent_start_failure(state_path, now=now) and daemon_provably_dead(state_path)


def record_start_failure(state_path: str | Path) -> None:
    marker = _marker_path(state_path)
    with suppress(OSError):
        marker.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        descriptor = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(json.dumps({"failed_at": time.time()}))


def clear_start_failure(state_path: str | Path) -> None:
    with suppress(OSError):
        _marker_path(state_path).unlink()


__all__ = [
    "DEAD_DAEMON_REASON_CODE",
    "FAILED_START_WINDOW_SECONDS",
    "clear_start_failure",
    "daemon_provably_dead",
    "recent_start_failure",
    "record_start_failure",
    "should_fail_fast",
]
