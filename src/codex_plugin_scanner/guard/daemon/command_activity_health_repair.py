"""Self-repair for degraded command-activity evidence health.

A single failed hook write leaves the evidence store flagged as degraded until a
later write, maintenance run or repair probe succeeds. When the dashboard reads
command activity while that flag is set and no failure has been recorded for a
while, the daemon runs the same probe and maintenance batch Protect repair runs,
so a transient failure does not leave a warning the user cannot clear. The probe
and maintenance are native store operations; this module only decides when to
call them.
"""

from __future__ import annotations

import sqlite3
import threading
import time
from collections.abc import Callable, Mapping
from datetime import datetime, timezone
from typing import Final

from ..config import load_guard_config
from ..store import GuardStore
from .server_control_connect_flow import _repair_command_activity_persistence_health

COMMAND_ACTIVITY_AUTO_REPAIR_INTERVAL_SECONDS: Final = 60.0
"""Wait after an attempt, whatever it found."""
COMMAND_ACTIVITY_HEALTH_CHECK_INTERVAL_SECONDS: Final = 5.0
COMMAND_ACTIVITY_REPAIR_QUIET_SECONDS: Final = 600.0
"""A failure newer than this stays visible: hooks that keep failing keep
refreshing it, so the notice is only cleared once failures have stopped."""

_attempt_lock = threading.Lock()
_next_attempt_by_home: dict[str, float] = {}
_check_lock = threading.Lock()
_last_check_by_home: dict[str, float] = {}


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def command_activity_health_degraded(payload: Mapping[str, object]) -> bool:
    health = payload.get("health")
    return isinstance(health, Mapping) and health.get("status") == "degraded"


def auto_repair_command_activity_health(
    store: GuardStore,
    *,
    clock: Callable[[], float] = time.monotonic,
    now: Callable[[], datetime] = _utc_now,
) -> bool:
    """Run one rate-limited repair attempt; return whether the probe ran.

    Concurrent callers skip instead of waiting. A store whose last failure is
    recent is left alone until the quiet window has passed, and a store that
    stays broken is probed once per interval rather than on every dashboard
    poll. Failures are swallowed: the health payload the caller reads next is
    the authoritative result.
    """

    home = str(store.guard_home)
    if not _attempt_lock.acquire(blocking=False):
        return False
    try:
        started = clock()
        next_attempt = _next_attempt_by_home.get(home)
        if next_attempt is not None and started < next_attempt:
            return False
        try:
            health = store.get_command_activity_persistence_health()
        except (OSError, RuntimeError, TypeError, ValueError, sqlite3.Error):
            _next_attempt_by_home[home] = started + COMMAND_ACTIVITY_AUTO_REPAIR_INTERVAL_SECONDS
            return False
        if health.active_error_count == 0:
            return False
        failed_at = health.last_error_at
        if failed_at is not None:
            if failed_at.tzinfo is None:
                failed_at = failed_at.replace(tzinfo=timezone.utc)
            age = (now() - failed_at).total_seconds()
            if age < COMMAND_ACTIVITY_REPAIR_QUIET_SECONDS:
                _next_attempt_by_home[home] = started + COMMAND_ACTIVITY_REPAIR_QUIET_SECONDS - max(age, 0.0)
                return False
        _next_attempt_by_home[home] = started + COMMAND_ACTIVITY_AUTO_REPAIR_INTERVAL_SECONDS
        try:
            config = load_guard_config(store.guard_home)
            _repair_command_activity_persistence_health(store)
            store.maintain_command_activity(now=now(), detail_retain_days=config.evidence_retain_days)
        except (OSError, RuntimeError, TypeError, ValueError, sqlite3.Error):
            pass
        return True
    finally:
        _attempt_lock.release()


def auto_repair_command_activity_health_if_degraded(
    store: GuardStore,
    *,
    clock: Callable[[], float] = time.monotonic,
    now: Callable[[], datetime] = _utc_now,
) -> bool:
    """Check stored health every few seconds at most and repair it when degraded.

    Routes whose payload does not already carry command-activity health, such as
    the runtime snapshot behind Home and Protect, call this before reading it.
    """

    home = str(store.guard_home)
    with _check_lock:
        checked = clock()
        last = _last_check_by_home.get(home)
        if last is not None and checked - last < COMMAND_ACTIVITY_HEALTH_CHECK_INTERVAL_SECONDS:
            return False
        _last_check_by_home[home] = checked
    return auto_repair_command_activity_health(store, clock=clock, now=now)


def reset_command_activity_auto_repair() -> None:
    """Forget previous checks and attempts. Tests use this to start from a clean limiter."""

    with _attempt_lock:
        _next_attempt_by_home.clear()
    with _check_lock:
        _last_check_by_home.clear()
