"""`hol-guard daemon repair` is bounded: a held start lock yields a typed answer.

Before this, the repair waited on the daemon start lock without a limit, so a
start that never finished left the one command the hook names as the recovery
hanging with it.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_daemon_manage as manager
from codex_plugin_scanner.guard.cli import commands_support_service
from codex_plugin_scanner.guard.runtime_health import runtime_repair


def _stub_repair_steps(monkeypatch: pytest.MonkeyPatch, events: list[str]) -> None:
    monkeypatch.setattr(runtime_repair, "repair_approval_center_locator", lambda _home: {"repaired": True})
    monkeypatch.setattr(runtime_repair, "verified_live_guard_daemon_identity", lambda _home: None)
    monkeypatch.setattr(
        runtime_repair, "retire_all_guard_daemons_for_home", lambda _home: events.append("retire") or []
    )
    monkeypatch.setattr(runtime_repair, "guard_daemon_retirement_is_complete", lambda _home: True)
    monkeypatch.setattr(runtime_repair, "clear_guard_daemon_state", lambda _home: None)
    monkeypatch.setattr(
        runtime_repair,
        "ensure_guard_daemon_after_update",
        lambda _home, *, home_dir: events.append("ensure") or "http://127.0.0.1:5474",
    )
    monkeypatch.setattr(runtime_repair, "_rebind_cursor_hooks_best_effort", lambda _home, *, home_dir: {})


def _protected_state(guard_home: Path) -> dict[str, bytes]:
    guard_home.mkdir(parents=True, exist_ok=True)
    files = {
        "guard.db": b"approvals and audit rows",
        "config.toml": b"policy = 'review'\n",
        "daemon-auth-token": b"credential",
        "daemon-state.json": b'{"port": 5474}',
    }
    for name, content in files.items():
        (guard_home / name).write_bytes(content)
    return files


def _hold_start_lock(guard_home: Path) -> tuple[threading.Event, threading.Thread]:
    held = threading.Event()
    release = threading.Event()

    def hold() -> None:
        with manager.guard_daemon_start_lock(guard_home):
            held.set()
            release.wait(30)

    thread = threading.Thread(target=hold, daemon=True)
    thread.start()
    assert held.wait(5)
    return release, thread


def test_repair_waits_a_bounded_time_for_a_held_start_lock_and_changes_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    guard_home = tmp_path / "guard-home"
    home_dir = tmp_path / "home"
    home_dir.mkdir()
    events: list[str] = []
    _stub_repair_steps(monkeypatch, events)
    files = _protected_state(guard_home)
    release, holder = _hold_start_lock(guard_home)
    try:
        started = time.monotonic()
        with pytest.raises(runtime_repair.DaemonRepairBusyError) as busy:
            runtime_repair.repair_guard_daemon_runtime(guard_home, home_dir=home_dir, lock_timeout_seconds=0.3)
        elapsed = time.monotonic() - started
    finally:
        release.set()
        holder.join(5)

    assert 0.25 <= elapsed < 5.0
    assert busy.value.reason_code == "daemon_repair_busy"
    assert "hol-guard daemon status" in busy.value.recovery
    assert events == []
    assert {name: (guard_home / name).read_bytes() for name in files} == files


def test_concurrent_repairs_each_return_the_busy_error_and_a_later_repair_runs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    guard_home = tmp_path / "guard-home"
    home_dir = tmp_path / "home"
    home_dir.mkdir()
    events: list[str] = []
    _stub_repair_steps(monkeypatch, events)
    _protected_state(guard_home)
    release, holder = _hold_start_lock(guard_home)
    outcomes: list[str] = []

    def attempt() -> None:
        try:
            runtime_repair.repair_guard_daemon_runtime(guard_home, home_dir=home_dir, lock_timeout_seconds=0.3)
            outcomes.append("repaired")
        except runtime_repair.DaemonRepairBusyError:
            outcomes.append("busy")

    attempts = [threading.Thread(target=attempt) for _ in range(3)]
    started = time.monotonic()
    for thread in attempts:
        thread.start()
    for thread in attempts:
        thread.join(10)
    elapsed = time.monotonic() - started
    release.set()
    holder.join(5)

    assert outcomes == ["busy"] * 3
    assert elapsed < 8.0
    assert events == []
    result = runtime_repair.repair_guard_daemon_runtime(guard_home, home_dir=home_dir, lock_timeout_seconds=5.0)
    assert result["runtime_status"] == "restarted"
    assert events == ["retire", "ensure"]


def test_a_stale_start_lock_file_does_not_block_repair(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    guard_home = tmp_path / "guard-home"
    home_dir = tmp_path / "home"
    home_dir.mkdir()
    events: list[str] = []
    _stub_repair_steps(monkeypatch, events)
    _protected_state(guard_home)
    # A process that died holding the lock leaves the file; the lock died with it.
    (guard_home / manager._START_LOCK_FILE).write_bytes(b"12345")
    (guard_home / "daemon-start-progress.json").write_text('{"pid": 12345}', encoding="utf-8")

    started = time.monotonic()
    result = runtime_repair.repair_guard_daemon_runtime(guard_home, home_dir=home_dir, lock_timeout_seconds=5.0)

    assert time.monotonic() - started < 5.0
    assert result["runtime_status"] == "restarted"
    assert events == ["retire", "ensure"]


def test_daemon_repair_command_prints_a_typed_busy_state_and_exits_nonzero(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    guard_home = tmp_path / "guard-home"
    files = _protected_state(guard_home)
    monkeypatch.setattr(commands_support_service, "_repair_resident_update_marker", lambda _home: None)

    def busy(_home: Path, *, home_dir: Path | None = None) -> dict[str, object]:
        raise runtime_repair.DaemonRepairBusyError(90.0)

    monkeypatch.setattr(commands_support_service, "repair_guard_daemon_runtime", busy)

    assert commands_support_service._handle_daemon_repair(guard_home, True) == 1

    payload = json.loads(capsys.readouterr().out)
    daemon = payload.get("daemon", payload)
    assert daemon["reason_code"] == "daemon_repair_busy"
    assert daemon["repaired"] is False
    assert "hol-guard daemon status" in daemon["recovery"]
    assert {name: (guard_home / name).read_bytes() for name in files} == files


def test_repair_without_a_timeout_still_waits_for_the_lock(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    guard_home = tmp_path / "guard-home"
    home_dir = tmp_path / "home"
    home_dir.mkdir()
    events: list[str] = []
    _stub_repair_steps(monkeypatch, events)
    _protected_state(guard_home)
    release, holder = _hold_start_lock(guard_home)
    threading.Timer(0.4, release.set).start()

    result = runtime_repair.repair_guard_daemon_runtime(guard_home, home_dir=home_dir, lock_timeout_seconds=None)
    holder.join(5)

    assert result["runtime_status"] == "restarted"


_HOLDER = """
import sys
from pathlib import Path
from codex_plugin_scanner.guard import native_daemon_manage as manager

with manager.guard_daemon_start_lock(Path(sys.argv[1])):
    print("held", flush=True)
    sys.stdin.readline()
"""


def test_repair_is_bounded_when_a_separate_process_holds_the_start_lock(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    guard_home = tmp_path / "guard-home"
    home_dir = tmp_path / "home"
    home_dir.mkdir()
    events: list[str] = []
    _stub_repair_steps(monkeypatch, events)
    files = _protected_state(guard_home)
    source_root = Path(manager.__file__).resolve().parents[2]
    env = {**os.environ, "PYTHONPATH": str(source_root)}
    holder = subprocess.Popen(
        [sys.executable, "-c", _HOLDER, str(guard_home)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        env=env,
        text=True,
    )
    try:
        assert holder.stdout is not None
        assert holder.stdout.readline().strip() == "held"
        started = time.monotonic()
        with pytest.raises(runtime_repair.DaemonRepairBusyError):
            runtime_repair.repair_guard_daemon_runtime(guard_home, home_dir=home_dir, lock_timeout_seconds=0.5)
        assert time.monotonic() - started < 5.0
        assert events == []
        assert {name: (guard_home / name).read_bytes() for name in files} == files
    finally:
        assert holder.stdin is not None
        holder.stdin.write("\n")
        holder.stdin.flush()
        holder.wait(10)

    result = runtime_repair.repair_guard_daemon_runtime(guard_home, home_dir=home_dir, lock_timeout_seconds=5.0)
    assert result["runtime_status"] == "restarted"
    assert events == ["retire", "ensure"]
