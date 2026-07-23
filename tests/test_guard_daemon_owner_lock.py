"""Cross-runtime daemon ownership coverage."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.daemon import manager


def test_daemon_owner_lock_rejects_second_runtime(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    guard_home = tmp_path / "guard-home"
    monkeypatch.setattr(manager, "_guard_daemon_process_inventory_for_guard_home", lambda _home: [])
    owner = manager.acquire_guard_daemon_owner_lock(guard_home)

    with pytest.raises(RuntimeError, match="already active"):
        manager.acquire_guard_daemon_owner_lock(guard_home)

    manager.release_guard_daemon_owner_lock(owner)
    replacement = manager.acquire_guard_daemon_owner_lock(guard_home)
    manager.release_guard_daemon_owner_lock(replacement)


def test_daemon_owner_lock_rejects_existing_same_home_process(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        manager,
        "_guard_daemon_process_inventory_for_guard_home",
        lambda _home: [(4242, 5474)],
    )

    with pytest.raises(RuntimeError, match="already active"):
        manager.acquire_guard_daemon_owner_lock(tmp_path / "guard-home")
