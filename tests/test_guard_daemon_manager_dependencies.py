"""Lifecycle dependency replacement must retain shared manager ownership."""

from pathlib import Path
from types import SimpleNamespace
from typing import BinaryIO

import pytest

from codex_plugin_scanner.guard.daemon import manager
from codex_plugin_scanner.guard.daemon.manager import ensure_guard_daemon


def test_launch_preflight_reads_the_current_manager_environment(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def reject_launch(_home: Path | None) -> Path:
        raise AssertionError("preflight must stop before the launcher validates a home")

    monkeypatch.setattr(manager, "os", SimpleNamespace(environ={"HOL_GUARD_DESKTOP_PREFLIGHT": "true"}))
    monkeypatch.setattr(manager, "_trusted_daemon_home", reject_launch)

    with pytest.raises(RuntimeError, match="disabled during Desktop preflight"):
        ensure_guard_daemon(tmp_path)


def test_owner_lock_rechecks_current_inventory_and_releases_on_rejection(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    inventories = iter([[], [(manager.os.getpid() + 1, 4781)]])
    handles: list[BinaryIO] = []
    released: list[BinaryIO] = []

    def claim(handle: BinaryIO) -> bool:
        handles.append(handle)
        return True

    def release(handle: BinaryIO) -> None:
        assert not handle.closed
        released.append(handle)

    monkeypatch.setattr(manager, "_guard_daemon_process_inventory_for_guard_home", lambda _home: next(inventories))
    monkeypatch.setattr(manager, "_try_lock_daemon_file", claim)
    monkeypatch.setattr(manager, "_unlock_daemon_start_file", release)

    with pytest.raises(RuntimeError, match="already active"):
        manager.acquire_guard_daemon_owner_lock(tmp_path / "guard-home")

    assert len(handles) == 1
    assert released == handles
    assert handles[0].closed
    assert next(inventories, None) is None


def test_state_write_exception_releases_current_manager_lock_and_registry(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    registry = {}
    handles: list[BinaryIO] = []
    released: list[BinaryIO] = []
    guard_home = tmp_path / "guard-home"
    monkeypatch.setattr(manager, "_STATE_WRITE_LOCKS", registry)
    monkeypatch.setattr(manager, "_lock_daemon_start_file", handles.append)
    monkeypatch.setattr(manager, "_unlock_daemon_start_file", released.append)

    with pytest.raises(ValueError, match="simulated write failure"), manager._guard_daemon_state_write_lock(guard_home):
        assert str(guard_home.resolve()) in registry
        assert not handles[0].closed
        raise ValueError("simulated write failure")

    assert len(handles) == 1
    assert released == handles
    assert handles[0].closed
    lock = registry[str(guard_home.resolve())]
    assert lock.acquire(blocking=False)
    lock.release()
