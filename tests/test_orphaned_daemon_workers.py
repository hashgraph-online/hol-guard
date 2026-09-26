"""Detached hook workers must die with the daemon that spawned them."""

from __future__ import annotations

import os
import signal
import time

import pytest

from codex_plugin_scanner.guard.daemon.orphaned_daemon_workers import (
    HOOK_WORKER_COMMAND_MARKER,
    ProcessSnapshot,
    orphaned_daemon_workers,
    parse_process_snapshot,
    terminate_orphaned_daemon_workers,
    with_hook_worker_command_marker,
)

_CORE = "/opt/Application Support/hol-guard-desktop/core/versions/3.6.3/hol-guard"
_DAEMON = f"{_CORE} daemon --serve --guard-home /opt/guard-home --home /opt/home --port 5474"
_WORKER = f"{_CORE} --multiprocessing-fork tracker_fd=20 pipe_handle=17"
_TRACKER = f"{_CORE} -B -S -I -c from multiprocessing.resource_tracker import main;main(18)"
_OTHER_DAEMON = "/opt/runner/versions/3.0.193/hol-guard daemon --serve --guard-home /opt/other-home --port 9"
_OTHER_WORKER = "/opt/runner/versions/3.0.193/hol-guard --multiprocessing-fork tracker_fd=7 pipe_handle=8"
_PYTHON_WORKER = (
    "/usr/bin/python3 -c from multiprocessing.spawn import spawn_main; spawn_main(tracker_fd=5, pipe_handle=6) "
    f"--multiprocessing-fork {HOOK_WORKER_COMMAND_MARKER}"
)


def _line(pid: int, ppid: int, state: str, command: str) -> str:
    return f"{pid} {ppid} {state} {command}"


def test_live_daemon_workers_stay_and_orphans_are_selected() -> None:
    processes = parse_process_snapshot(
        "\n".join(
            (
                _line(100, 1, "Ss", _DAEMON),
                _line(101, 100, "S", _WORKER),
                _line(102, 100, "S", _TRACKER),
                _line(103, 101, "S", _WORKER),
                _line(200, 1, "Z", _DAEMON),
                _line(201, 200, "S", _WORKER),
                _line(202, 1, "S", _TRACKER),
                _line(203, 1, "S", _PYTHON_WORKER),
                _line(300, 1, "S", _OTHER_DAEMON),
                _line(301, 300, "S", _OTHER_WORKER),
                _line(400, 1, "S", "/usr/bin/python3 -c from multiprocessing.spawn import spawn_main"),
                _line(401, 1, "S", "echo /opt/hol-guard --multiprocessing-fork"),
            )
        )
    )

    assert [process.pid for process in orphaned_daemon_workers(processes)] == [201, 202, 203]


def test_python_module_daemon_anchors_its_worker() -> None:
    daemon = (
        "/usr/bin/python3 -m codex_plugin_scanner.cli guard daemon --serve --guard-home /opt/guard-home --port 5474"
    )
    processes = parse_process_snapshot(
        "\n".join(
            (
                _line(10, 1, "S", daemon),
                _line(11, 10, "S", _WORKER),
            )
        )
    )

    assert orphaned_daemon_workers(processes) == []


def test_terminate_signals_the_worker_group_then_forces_a_survivor(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[str, int, int]] = []
    alive = {50}

    monkeypatch.setattr(os, "getpgid", lambda pid: pid)
    monkeypatch.setattr(os, "killpg", lambda pid, sig: calls.append(("group", pid, sig)))

    def kill(pid: int, sig: int) -> None:
        calls.append(("pid", pid, sig))
        if sig == 0 and pid not in alive:
            raise ProcessLookupError
        if sig == signal.SIGKILL:
            alive.discard(pid)

    monkeypatch.setattr(os, "kill", kill)
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.orphaned_daemon_workers.time.sleep",
        lambda _seconds: None,
    )

    terminate_orphaned_daemon_workers(
        [ProcessSnapshot(50, 1, "S", _WORKER)],
        command_for_pid=lambda pid: _WORKER if pid == 50 else None,
        start_token_for_pid=lambda pid: "posix:start" if pid == 50 else None,
        grace_seconds=0,
    )

    assert ("group", 50, signal.SIGTERM) in calls
    assert ("group", 50, signal.SIGKILL) in calls


def test_replacement_start_reaps_orphaned_workers_before_choosing_a_port(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from codex_plugin_scanner.guard.daemon import manager

    order: list[str] = []
    monkeypatch.setattr(manager, "_live_or_newer_daemon_url", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(manager, "_schedule_stale_ephemeral_guard_daemon_reap", lambda **_kwargs: None)
    monkeypatch.setattr(manager, "load_guard_daemon_url", lambda _home: None)
    monkeypatch.setattr(manager, "_adopt_existing_guard_daemon", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(manager, "_load_state", lambda _home: None)
    monkeypatch.setattr(manager, "_guard_daemon_start_in_progress", lambda _home: False)
    monkeypatch.setattr(manager, "clear_guard_daemon_state", lambda _home: order.append("clear"))
    monkeypatch.setattr(manager, "reap_orphaned_daemon_workers", lambda **_kwargs: order.append("reap"))
    monkeypatch.setattr(
        manager,
        "_candidate_ports",
        lambda *_args, **_kwargs: order.append("ports") or [],
    )
    home = tmp_path / "home"
    guard_home = home / ".hol-guard"
    home.mkdir()
    guard_home.mkdir()

    with pytest.raises(RuntimeError, match="approval center did not start"):
        manager.ensure_guard_daemon(guard_home, home_dir=home, start_timeout=1)

    assert order == ["clear", "reap", "ports"]


def test_daemon_retirement_reaps_orphaned_workers(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    from codex_plugin_scanner.guard.daemon import manager

    seen: list[bool] = []
    monkeypatch.setattr(manager, "_guard_daemon_process_inventory_for_guard_home", lambda _home: [])
    monkeypatch.setattr(manager, "load_authenticated_daemon_state", lambda _home: None)
    monkeypatch.setattr(manager, "load_authenticated_guard_daemon_pending_launch", lambda _home: None)
    monkeypatch.setattr(manager, "reap_orphaned_daemon_workers", lambda **_kwargs: seen.append(True))

    assert manager.retire_all_guard_daemons_for_home(tmp_path / "guard-home") == []
    assert seen == [True]


def test_terminate_does_not_signal_the_current_process_or_init(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[int] = []
    monkeypatch.setattr(os, "getpgid", lambda pid: calls.append(pid) or pid)
    monkeypatch.setattr(os, "killpg", lambda *_args: None)

    terminate_orphaned_daemon_workers(
        [
            ProcessSnapshot(0, 0, "S", _WORKER),
            ProcessSnapshot(1, 0, "S", _WORKER),
            ProcessSnapshot(os.getpid(), 1, "S", _WORKER),
        ],
        command_for_pid=lambda _pid: _WORKER,
        start_token_for_pid=lambda _pid: "posix:start",
        grace_seconds=0,
    )

    assert calls == []


def test_terminate_skips_a_reused_pid(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[int, int]] = []
    monkeypatch.setattr(os, "getpgid", lambda pid: pid)
    monkeypatch.setattr(os, "killpg", lambda pid, sig: calls.append((pid, sig)))

    terminate_orphaned_daemon_workers(
        [ProcessSnapshot(50, 1, "S", _WORKER)],
        command_for_pid=lambda _pid: "/usr/bin/python3 unrelated",
        start_token_for_pid=lambda _pid: "posix:other",
        grace_seconds=0,
    )

    assert calls == []


def test_terminate_does_not_force_kill_after_the_start_token_changes(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[int] = []
    tokens = iter(("posix:original", "posix:replacement"))
    monkeypatch.setattr(os, "getpgid", lambda pid: pid)
    monkeypatch.setattr(os, "killpg", lambda pid, sig: calls.append(sig))

    terminate_orphaned_daemon_workers(
        [ProcessSnapshot(50, 1, "S", _WORKER)],
        command_for_pid=lambda _pid: _WORKER,
        start_token_for_pid=lambda _pid: next(tokens),
        grace_seconds=0,
    )

    assert calls == [signal.SIGTERM]


def test_marked_python_command_is_attributable() -> None:
    command = with_hook_worker_command_marker(
        ["/usr/bin/python3", "-c", "from multiprocessing.spawn import spawn_main", "--multiprocessing-fork"]
    )

    assert command[-1] == HOOK_WORKER_COMMAND_MARKER
    assert with_hook_worker_command_marker(command) == command


def test_reap_returns_when_the_start_deadline_has_passed(monkeypatch: pytest.MonkeyPatch) -> None:
    from codex_plugin_scanner.guard.daemon import manager

    def fail_query(*_args, **_kwargs):
        raise AssertionError("process query ran after the deadline")

    monkeypatch.setattr(manager, "_bounded_process_query_stdout", fail_query)

    manager.reap_orphaned_daemon_workers(deadline=time.monotonic() - 1)
