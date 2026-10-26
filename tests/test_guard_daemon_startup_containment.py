# pyright: reportPrivateUsage=false
"""Unconfirmed startup cleanup retains service ownership for a later retry."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.daemon import manager
from codex_plugin_scanner.guard.daemon.server import GuardDaemonServer
from codex_plugin_scanner.guard.daemon.service_lifecycle import contain_failed_service_start
from codex_plugin_scanner.guard.store import GuardStore


def test_failed_server_close_retains_owner_until_cleanup_retry(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = GuardStore(tmp_path / "guard-home")
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0, idle_timeout_seconds=0)
    daemon._owner_lock = manager.acquire_guard_daemon_owner_lock(store.guard_home)
    original_close = daemon._server.server_close
    close_calls = 0

    def failed_close() -> None:
        nonlocal close_calls
        close_calls += 1
        raise OSError("synthetic socket cleanup failure")

    monkeypatch.setattr(daemon._server, "server_close", failed_close)
    try:
        startup_error = RuntimeError("synthetic startup failure")
        contain_failed_service_start(daemon, startup_error, serve_thread_started=False)
        assert close_calls >= 2
        assert daemon._owner_lock is not None
        assert daemon._is_quarantined()
        with pytest.raises(RuntimeError, match="already active"):
            _ = manager.acquire_guard_daemon_owner_lock(store.guard_home)
        if hasattr(startup_error, "add_note"):
            assert (
                "Guard retained daemon ownership because startup containment was unconfirmed."
                in startup_error.__notes__
            )
    finally:
        monkeypatch.setattr(daemon._server, "server_close", original_close)
        assert daemon._finish_service()
    assert daemon._owner_lock is None
    assert not daemon._is_quarantined()
    replacement_owner = manager.acquire_guard_daemon_owner_lock(store.guard_home)
    manager.release_guard_daemon_owner_lock(replacement_owner)
