"""Detached hook workers must die with the daemon that spawned them."""

from __future__ import annotations

import os
import signal

import pytest

from codex_plugin_scanner.guard.daemon.orphaned_hook_workers import (
    orphaned_hook_worker_pids,
    parse_process_snapshot,
    terminate_orphaned_hook_workers,
)

_CORE = "/opt/Application Support/hol-guard-desktop/core/versions/3.6.3/hol-guard"
_DAEMON = f"{_CORE} daemon --serve --guard-home /opt/guard-home --home /opt/home --port 5474"
_WORKER = f"{_CORE} --multiprocessing-fork tracker_fd=20 pipe_handle=17"
_TRACKER = f"{_CORE} -B -S -I -c from multiprocessing.resource_tracker import main;main(18)"
_OTHER_DAEMON = "/opt/runner/versions/3.0.193/hol-guard daemon --serve --guard-home /opt/other-home --port 9"
_OTHER_WORKER = "/opt/runner/versions/3.0.193/hol-guard --multiprocessing-fork tracker_fd=7 pipe_handle=8"


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
                _line(300, 1, "S", _OTHER_DAEMON),
                _line(301, 300, "S", _OTHER_WORKER),
                _line(400, 1, "S", "/usr/bin/python3 -c from multiprocessing.spawn import spawn_main"),
                _line(401, 1, "S", "echo /opt/hol-guard --multiprocessing-fork"),
            )
        )
    )

    assert orphaned_hook_worker_pids(processes) == [201, 202]


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

    assert orphaned_hook_worker_pids(processes) == []


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
        "codex_plugin_scanner.guard.daemon.orphaned_hook_workers.time.sleep",
        lambda _seconds: None,
    )

    terminate_orphaned_hook_workers([50], grace_seconds=0)

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
    monkeypatch.setattr(manager, "reap_orphaned_hook_workers", lambda: order.append("reap"))
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
    monkeypatch.setattr(manager, "reap_orphaned_hook_workers", lambda: seen.append(True))

    assert manager.retire_all_guard_daemons_for_home(tmp_path / "guard-home") == []
    assert seen == [True]


def test_terminate_does_not_signal_the_current_process_or_init(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[int] = []
    monkeypatch.setattr(os, "getpgid", lambda pid: calls.append(pid) or pid)
    monkeypatch.setattr(os, "killpg", lambda *_args: None)

    terminate_orphaned_hook_workers([0, 1, os.getpid()], grace_seconds=0)

    assert calls == []
