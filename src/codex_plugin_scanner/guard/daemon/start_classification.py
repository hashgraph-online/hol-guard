"""Classify a spawned Guard daemon that missed its start deadline.

A daemon whose state URL never appeared is either dead, still progressing, or
blocked. Only a progressing daemon is preserved: evidence must attribute to the
spawned process or its descendants so a foreign process can never veto cleanup.
"""

from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from ..mdm.file_lock import release_file_lock
from .file_locking import try_lock_daemon_file
from .lifecycle_journal import load_daemon_lifecycle_events

_PPID_WALK_LIMIT = 16


class GuardDaemonStillStartingError(RuntimeError):
    """Raised when the spawned daemon is still starting; callers must not kill it."""


@dataclass(frozen=True)
class SpawnedDaemonSignals:
    """Evidence collected for one spawned daemon at the start deadline."""

    pending_launch_present: bool
    lock_held_by_spawned_tree: bool
    journal_start_requested_after: bool


def classify_spawned_daemon(
    process: subprocess.Popen[bytes],
    *,
    pending_launch_present: bool,
    lock_held_by_spawned_tree: bool,
    journal_start_requested_after: bool,
) -> Literal["progressing", "dead", "blocked"]:
    """Classify a spawned daemon whose state URL never appeared before the deadline."""

    if process.poll() is not None:
        return "dead"
    if pending_launch_present and (lock_held_by_spawned_tree or journal_start_requested_after):
        return "progressing"
    return "blocked"


def collect_spawned_daemon_signals(
    guard_home: Path,
    *,
    process: subprocess.Popen[bytes],
    spawned_at_ns: int,
    pending_creation_time: int | None,
) -> SpawnedDaemonSignals:
    return SpawnedDaemonSignals(
        pending_launch_present=_spawned_guard_daemon_pending_launch_present(
            guard_home,
            process=process,
            creation_time=pending_creation_time,
        ),
        lock_held_by_spawned_tree=spawned_daemon_owner_lock_held(guard_home, root_pid=process.pid),
        journal_start_requested_after=daemon_journal_records_start_requested_after(
            guard_home,
            root_pid=process.pid,
            since_ns=spawned_at_ns,
        ),
    )


def daemon_still_starting_evidence_present(guard_home: Path, *, root_pid: int, spawned_at_ns: int) -> bool:
    """Re-check progress evidence for a recorded still-starting daemon pid."""

    return spawned_daemon_owner_lock_held(
        guard_home, root_pid=root_pid
    ) or daemon_journal_records_start_requested_after(
        guard_home,
        root_pid=root_pid,
        since_ns=spawned_at_ns,
    )


def _spawned_guard_daemon_pending_launch_present(
    guard_home: Path,
    *,
    process: subprocess.Popen[bytes],
    creation_time: int | None,
) -> bool:
    if os.name != "nt":
        # POSIX keeps no pending-launch file; the live child handle is the record.
        return True
    from . import manager as _manager

    pending = _manager.load_authenticated_guard_daemon_pending_launch(guard_home)
    return (
        isinstance(pending, dict)
        and pending.get("pid") == process.pid
        and pending.get("process_creation_time") == creation_time
    )


def daemon_owner_lock_is_held(guard_home: Path) -> bool:
    from . import manager as _manager

    try:
        with (guard_home / _manager._GUARD_DAEMON_OWNER_LOCK_FILE).open("a+b") as handle:
            if try_lock_daemon_file(handle):
                release_file_lock(handle)
                return False
            return True
    except OSError:
        return False


def spawned_daemon_owner_lock_held(guard_home: Path, *, root_pid: int) -> bool:
    """Attribute a held owner lock to the spawned tree before trusting it."""

    from . import manager as _manager

    if not daemon_owner_lock_is_held(guard_home):
        return False
    inventory = _manager._guard_daemon_process_inventory_for_guard_home(guard_home)
    if not inventory:
        return False
    return all(_pid_in_process_tree(pid, root_pid) for pid, _port in inventory)


def daemon_journal_records_start_requested_after(
    guard_home: Path,
    *,
    root_pid: int,
    since_ns: int,
) -> bool:
    """Find a newer ``start_requested`` event written by ``root_pid``'s tree."""

    try:
        events = load_daemon_lifecycle_events(guard_home, limit=128)
    except OSError:
        return False
    for event in events:
        if event.get("event") != "start_requested" or event.get("recorded_at_ns", 0) <= since_ns:
            continue
        event_pid = event.get("pid")
        if isinstance(event_pid, int) and _pid_in_process_tree(event_pid, root_pid):
            return True
    return False


def _pid_in_process_tree(pid: int, root_pid: int) -> bool:
    from . import manager as _manager

    if pid == root_pid:
        return True
    if os.name == "nt":
        root_cmd = _manager.windows_processes.windows_process_command_line(root_pid)
        pid_cmd = _manager.windows_processes.windows_process_command_line(pid)
        return root_cmd is not None and pid_cmd is not None and _manager._same_daemon_invocation(root_cmd, pid_cmd)
    current = pid
    for _ in range(_PPID_WALK_LIMIT):
        parent = _manager._guard_daemon_parent_pid(current)
        if parent is None or parent <= 1:
            return False
        if parent == root_pid:
            return True
        current = parent
    return False


__all__ = [
    "GuardDaemonStillStartingError",
    "SpawnedDaemonSignals",
    "classify_spawned_daemon",
    "collect_spawned_daemon_signals",
    "daemon_journal_records_start_requested_after",
    "daemon_owner_lock_is_held",
    "daemon_still_starting_evidence_present",
    "spawned_daemon_owner_lock_held",
]
