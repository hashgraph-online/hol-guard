"""A launch that died before its handoff must not block every later daemon start."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.daemon import manager as daemon_manager_module

_PENDING_PID = 64_321
_PENDING_MARKER = "posix:launch-start"
_PENDING_CREATION_TIME = 4_242_424


class _ReplacementStartedError(Exception):
    pass


def _write_abandoned_launch(guard_home: Path) -> dict[str, object]:
    daemon_manager_module._ensure_private_directory(guard_home)
    launch_nonce = "a" * daemon_manager_module._GUARD_DAEMON_LAUNCH_NONCE_HEX_LENGTH
    payload: dict[str, object] = {
        "state_kind": "daemon_launch_pending",
        "guard_home": str(guard_home.resolve()),
        "pid": _PENDING_PID,
        "port": 5410,
        "launch_nonce": launch_nonce,
        "launch_generation": launch_nonce,
        "generation": launch_nonce,
        "process_start_marker": _PENDING_MARKER,
        "process_creation_time": _PENDING_CREATION_TIME,
        "user": "launch-owner",
        "owner": "launch-owner",
        "runtime_fingerprint": "launch-runtime",
    }
    discovery_key = daemon_manager_module.ensure_daemon_discovery_key(guard_home)
    pending = daemon_manager_module.authenticate_daemon_state(payload, discovery_key=discovery_key)
    daemon_manager_module._write_private_atomic_text(
        daemon_manager_module._pending_launch_path(guard_home),
        json.dumps(pending, sort_keys=True),
    )
    loaded = daemon_manager_module.load_authenticated_guard_daemon_pending_launch(guard_home)
    assert loaded is not None
    assert daemon_manager_module._guard_daemon_pending_launch_is_generation_bound(loaded)
    return loaded


def _launch_root(monkeypatch, *, dead: bool, marker: str | None = None, creation_time: int | None = None) -> None:
    monkeypatch.setattr(daemon_manager_module, "_guard_daemon_pid_is_proven_dead", lambda pid: dead)
    monkeypatch.setattr(daemon_manager_module, "process_start_token", lambda pid: marker)
    monkeypatch.setattr(daemon_manager_module, "windows_process_creation_time", lambda pid: creation_time)


def _home_inventory(monkeypatch, inventory: list[object] | None) -> None:
    monkeypatch.setattr(
        daemon_manager_module,
        "_guard_daemon_process_inventory_for_guard_home",
        lambda *_args, **_kwargs: inventory,
    )


def test_dead_launch_without_a_daemon_stops_blocking_the_next_start(tmp_path, monkeypatch):
    guard_home = tmp_path / "guard-home"
    _write_abandoned_launch(guard_home)
    _launch_root(monkeypatch, dead=True)
    _home_inventory(monkeypatch, [])
    monkeypatch.setattr(daemon_manager_module, "_schedule_stale_ephemeral_guard_daemon_reap", lambda **_kwargs: None)
    monkeypatch.setattr(daemon_manager_module, "_live_or_newer_daemon_url", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(daemon_manager_module, "_adopt_existing_guard_daemon", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(daemon_manager_module, "_guard_daemon_start_in_progress", lambda _home: False)

    def start_replacement(_home: Path) -> None:
        raise _ReplacementStartedError

    # Clearing the old state is the first step of a replacement launch.
    monkeypatch.setattr(daemon_manager_module, "clear_guard_daemon_state", start_replacement)

    with pytest.raises(_ReplacementStartedError):
        daemon_manager_module.ensure_guard_daemon(guard_home, start_timeout=5.0)

    assert daemon_manager_module._guard_daemon_pending_launch_state_is_resolved(guard_home)


def test_dead_launch_is_tombstoned_once_the_home_runs_no_daemon(tmp_path, monkeypatch):
    guard_home = tmp_path / "guard-home"
    pending = _write_abandoned_launch(guard_home)
    _launch_root(monkeypatch, dead=True)
    _home_inventory(monkeypatch, [])

    assert daemon_manager_module._resolve_abandoned_guard_daemon_pending_launch(guard_home, pending)
    assert daemon_manager_module._pending_launch_path(guard_home).read_text() == "{}"


@pytest.mark.parametrize("inventory", [None, [object()]], ids=["unknown", "running"])
def test_dead_launch_is_kept_while_the_home_may_run_a_daemon(tmp_path, monkeypatch, inventory):
    guard_home = tmp_path / "guard-home"
    pending = _write_abandoned_launch(guard_home)
    _launch_root(monkeypatch, dead=True)
    _home_inventory(monkeypatch, inventory)

    assert not daemon_manager_module._resolve_abandoned_guard_daemon_pending_launch(guard_home, pending)
    assert not daemon_manager_module._guard_daemon_pending_launch_state_is_resolved(guard_home)


def test_live_launch_with_its_own_identity_is_kept(tmp_path, monkeypatch):
    guard_home = tmp_path / "guard-home"
    pending = _write_abandoned_launch(guard_home)
    _launch_root(monkeypatch, dead=False, marker=_PENDING_MARKER, creation_time=_PENDING_CREATION_TIME)
    _home_inventory(monkeypatch, [])

    assert not daemon_manager_module._resolve_abandoned_guard_daemon_pending_launch(guard_home, pending)
    assert not daemon_manager_module._guard_daemon_pending_launch_state_is_resolved(guard_home)


def test_live_launch_with_unreadable_identity_is_kept(tmp_path, monkeypatch):
    guard_home = tmp_path / "guard-home"
    pending = _write_abandoned_launch(guard_home)
    _launch_root(monkeypatch, dead=False)
    _home_inventory(monkeypatch, [])

    assert not daemon_manager_module._resolve_abandoned_guard_daemon_pending_launch(guard_home, pending)
    assert not daemon_manager_module._guard_daemon_pending_launch_state_is_resolved(guard_home)


def test_reused_pid_does_not_keep_a_dead_launch(tmp_path, monkeypatch):
    guard_home = tmp_path / "guard-home"
    pending = _write_abandoned_launch(guard_home)
    _launch_root(monkeypatch, dead=False, marker="posix:another-start", creation_time=_PENDING_CREATION_TIME + 1)
    _home_inventory(monkeypatch, [])

    assert daemon_manager_module._resolve_abandoned_guard_daemon_pending_launch(guard_home, pending)
    assert daemon_manager_module._guard_daemon_pending_launch_state_is_resolved(guard_home)


def test_replaced_receipt_is_not_cleared_for_an_older_launch(tmp_path, monkeypatch):
    guard_home = tmp_path / "guard-home"
    stale = _write_abandoned_launch(guard_home)
    _launch_root(monkeypatch, dead=True)
    _home_inventory(monkeypatch, [])

    assert not daemon_manager_module._resolve_abandoned_guard_daemon_pending_launch(
        guard_home, {**stale, "pid": _PENDING_PID + 1}
    )
    assert not daemon_manager_module._guard_daemon_pending_launch_state_is_resolved(guard_home)
    assert os.path.getsize(daemon_manager_module._pending_launch_path(guard_home)) > 2
