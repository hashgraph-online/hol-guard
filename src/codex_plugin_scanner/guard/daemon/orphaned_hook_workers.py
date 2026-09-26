"""Reap hook workers left behind when their daemon is stopped.

Hook workers call ``setsid()`` so a crash stays inside the worker. That also
means killing the daemon process does not kill them. The survivors keep the
local store open, and the replacement daemon blocks on that store before it
can publish daemon state. Desktop then treats the new CLI as offline and
restores the previous version.

A worker is orphaned when no live ``daemon --serve`` process remains in its
parent chain. Workers of a live daemon, including a daemon for another home,
are left alone.
"""

from __future__ import annotations

import os
import signal
import time
from dataclasses import dataclass

_HOL_GUARD_EXECUTABLES = frozenset(
    {
        "hol-guard",
        "hol-guard.exe",
        "plugin-guard",
        "plugin-guard.exe",
    }
)
_MAX_PARENT_HOPS = 8
_ORPHAN_REAP_GRACE_SECONDS = 1.0
_ORPHAN_REAP_POLL_SECONDS = 0.05


@dataclass(frozen=True, slots=True)
class ProcessSnapshot:
    pid: int
    ppid: int
    state: str
    command: str


def parse_process_snapshot(output: str) -> list[ProcessSnapshot]:
    """Parse ``ps -axww -o pid=,ppid=,state=,command=`` output."""

    processes: list[ProcessSnapshot] = []
    for line in output.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        pid_text, separator, rest = stripped.partition(" ")
        if separator == "" or not pid_text.isdigit():
            continue
        rest = rest.strip()
        ppid_text, separator, rest = rest.partition(" ")
        if separator == "" or not ppid_text.isdigit():
            continue
        rest = rest.strip()
        state, separator, command = rest.partition(" ")
        if separator == "" or not state or any(character.isspace() for character in state):
            continue
        processes.append(
            ProcessSnapshot(
                pid=int(pid_text),
                ppid=int(ppid_text),
                state=state,
                command=command.strip(),
            )
        )
    return processes


def orphaned_hook_worker_pids(processes: list[ProcessSnapshot]) -> list[int]:
    """Return detached Guard hook workers whose daemon is no longer live."""

    by_pid = {process.pid: process for process in processes}
    return sorted(
        process.pid
        for process in processes
        if process.pid > 1
        and _is_hol_guard_hook_worker(process.command)
        and not _has_live_daemon_ancestor(process, by_pid)
    )


def terminate_orphaned_hook_workers(
    pids: list[int],
    *,
    grace_seconds: float = _ORPHAN_REAP_GRACE_SECONDS,
) -> None:
    """Stop orphaned workers, then force any that ignore the first signal."""

    targets = [pid for pid in pids if pid > 1 and pid != os.getpid()]
    for pid in targets:
        _signal_worker(pid, signal.SIGTERM)
    deadline = time.monotonic() + max(0.0, grace_seconds)
    pending = [pid for pid in targets if _pid_is_alive(pid)]
    while pending and time.monotonic() < deadline:
        time.sleep(min(_ORPHAN_REAP_POLL_SECONDS, max(0.0, deadline - time.monotonic())))
        pending = [pid for pid in pending if _pid_is_alive(pid)]
    for pid in pending:
        _signal_worker(pid, signal.SIGKILL)


def _signal_worker(pid: int, sig: int) -> None:
    try:
        process_group = os.getpgid(pid)
    except OSError:
        return
    if process_group == pid:
        try:
            os.killpg(pid, sig)
            return
        except OSError:
            pass
    try:
        os.kill(pid, sig)
    except OSError:
        return


def _pid_is_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False
    return True


def _has_live_daemon_ancestor(
    process: ProcessSnapshot,
    by_pid: dict[int, ProcessSnapshot],
) -> bool:
    seen = {process.pid}
    current = by_pid.get(process.ppid)
    for _ in range(_MAX_PARENT_HOPS):
        if current is None or current.pid <= 1 or current.pid in seen:
            return False
        if not current.state.startswith("Z") and _is_hol_guard_daemon_serve(current.command):
            return True
        seen.add(current.pid)
        current = by_pid.get(current.ppid)
    return False


def _is_hol_guard_hook_worker(command: str) -> bool:
    fork_marker = " --multiprocessing-fork"
    fork_at = command.find(fork_marker)
    if fork_at > 0 and _is_absolute_hol_guard_executable(command[:fork_at]):
        return True
    tracker_marker = "from multiprocessing.resource_tracker import main"
    return tracker_marker in command and _leading_executable_is_hol_guard(command)


def _is_hol_guard_daemon_serve(command: str) -> bool:
    for marker in (" daemon --serve", " guard daemon --serve"):
        marker_at = command.find(marker)
        if marker_at <= 0:
            continue
        prefix = command[:marker_at]
        if _is_absolute_hol_guard_executable(prefix):
            return True
        if "codex_plugin_scanner.cli" in prefix and _prefix_launches_daemon(prefix):
            return True
    return False


def _prefix_launches_daemon(prefix: str) -> bool:
    return prefix.endswith(" guard") or prefix.endswith("codex_plugin_scanner.cli")


def _is_absolute_hol_guard_executable(prefix: str) -> bool:
    executable = prefix.strip().strip('"')
    if not executable.startswith("/") and not _is_windows_absolute(executable):
        return False
    name = executable.replace("\\", "/").rsplit("/", 1)[-1].lower()
    return name in _HOL_GUARD_EXECUTABLES


def _leading_executable_is_hol_guard(command: str) -> bool:
    stripped = command.strip().strip('"')
    if not stripped.startswith("/") and not _is_windows_absolute(stripped):
        return False
    for name in ("/hol-guard ", "/hol-guard.exe ", "/plugin-guard ", "/plugin-guard.exe "):
        marker_at = stripped.lower().find(name)
        if marker_at > 0 and " -" not in stripped[:marker_at]:
            return True
    return False


def _is_windows_absolute(value: str) -> bool:
    return len(value) > 2 and value[1] == ":" and value[2] in {"\\", "/"}
