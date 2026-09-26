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
from collections.abc import Callable
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
HOOK_WORKER_COMMAND_MARKER = "--hol-guard-hook-worker"

CommandReader = Callable[[int], str | None]
StartTokenReader = Callable[[int], str | None]


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


def with_hook_worker_command_marker(command: list[str]) -> list[str]:
    """Mark a spawned worker command so a later reaper can attribute it."""

    if HOOK_WORKER_COMMAND_MARKER in command:
        return list(command)
    return [*command, HOOK_WORKER_COMMAND_MARKER]


def orphaned_daemon_workers(processes: list[ProcessSnapshot]) -> list[ProcessSnapshot]:
    """Return detached Guard hook workers whose daemon is no longer live."""

    by_pid = {process.pid: process for process in processes}
    selected = [
        process
        for process in processes
        if process.pid > 1
        and process.pid != os.getpid()
        and _is_hol_guard_hook_worker(process.command)
        and not _has_live_daemon_ancestor(process, by_pid)
    ]
    return sorted(selected, key=lambda process: process.pid)


def terminate_orphaned_daemon_workers(
    workers: list[ProcessSnapshot],
    *,
    command_for_pid: CommandReader,
    start_token_for_pid: StartTokenReader,
    grace_seconds: float = _ORPHAN_REAP_GRACE_SECONDS,
) -> None:
    """Stop orphaned workers, then force any that ignore the first signal.

    Each signal is sent only when the pid still has the snapshotted command and
    the same process start token captured for that worker. A reused pid is skipped.
    """

    armed: list[tuple[ProcessSnapshot, str]] = []
    for worker in workers:
        if worker.pid <= 1 or worker.pid == os.getpid():
            continue
        token = _signal_matching_worker(
            worker,
            signal.SIGTERM,
            command_for_pid=command_for_pid,
            start_token_for_pid=start_token_for_pid,
            expected_token=None,
        )
        if token is not None:
            armed.append((worker, token))
    deadline = time.monotonic() + max(0.0, grace_seconds)
    pending = armed
    while pending and time.monotonic() < deadline:
        time.sleep(min(_ORPHAN_REAP_POLL_SECONDS, max(0.0, deadline - time.monotonic())))
        pending = [
            (worker, token)
            for worker, token in pending
            if _worker_identity_matches(
                worker,
                expected_token=token,
                command_for_pid=command_for_pid,
                start_token_for_pid=start_token_for_pid,
            )
        ]
    for worker, token in pending:
        _signal_matching_worker(
            worker,
            signal.SIGKILL,
            command_for_pid=command_for_pid,
            start_token_for_pid=start_token_for_pid,
            expected_token=token,
        )


def _signal_matching_worker(
    worker: ProcessSnapshot,
    sig: int,
    *,
    command_for_pid: CommandReader,
    start_token_for_pid: StartTokenReader,
    expected_token: str | None,
) -> str | None:
    token = _worker_identity_matches(
        worker,
        expected_token=expected_token,
        command_for_pid=command_for_pid,
        start_token_for_pid=start_token_for_pid,
    )
    if token is None:
        return None
    command_again = command_for_pid(worker.pid)
    if command_again is None or command_again.strip() != worker.command:
        return None
    _signal_worker(worker.pid, sig)
    return token


def _worker_identity_matches(
    worker: ProcessSnapshot,
    *,
    expected_token: str | None,
    command_for_pid: CommandReader,
    start_token_for_pid: StartTokenReader,
) -> str | None:
    command = command_for_pid(worker.pid)
    if command is None or command.strip() != worker.command:
        return None
    token = start_token_for_pid(worker.pid)
    if token is None or token == "":
        return None
    if expected_token is not None and token != expected_token:
        return None
    return token


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
    if tracker_marker in command and _leading_executable_is_hol_guard(command):
        return True
    return _is_marked_python_hook_worker(command)


def _is_hol_guard_daemon_serve(command: str) -> bool:
    frozen_at = command.find(" --_hol-guard-daemon-serve")
    if frozen_at > 0 and _is_absolute_hol_guard_executable(command[:frozen_at]):
        return True
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


def _is_marked_python_hook_worker(command: str) -> bool:
    if HOOK_WORKER_COMMAND_MARKER not in command.split():
        return False
    if "--multiprocessing-fork" not in command.split() and (
        "from multiprocessing.resource_tracker import main" not in command
    ):
        return False
    stripped = command.strip().strip('"')
    if not stripped.startswith("/") and not _is_windows_absolute(stripped):
        return False
    executable = stripped.split()[0].replace("\\", "/").rsplit("/", 1)[-1].lower()
    return executable.startswith("python")


def _is_windows_absolute(value: str) -> bool:
    return len(value) > 2 and value[1] == ":" and value[2] in {"\\", "/"}
