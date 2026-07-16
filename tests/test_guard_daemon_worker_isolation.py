"""Test-only daemon worker isolation and composition coverage."""

from __future__ import annotations

import threading
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.daemon import server as guard_daemon_module
from codex_plugin_scanner.guard.store import GuardStore


@pytest.mark.daemon_headless_refresh
def test_daemon_headless_refresh_stops_cleanly(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = GuardStore(tmp_path / "guard-home")
    synced = threading.Event()

    def _fake_sync(*, store: GuardStore) -> dict[str, object]:
        del store
        synced.set()
        return {"status": "synced"}

    monkeypatch.setattr(guard_daemon_module, "_run_headless_cloud_sync", _fake_sync)
    daemon = guard_daemon_module.GuardDaemonServer(store, host="127.0.0.1", port=0, idle_timeout_seconds=60)
    daemon._headless_cloud_sync_interval_seconds = 0.05

    daemon.start()
    assert synced.wait(timeout=1)
    daemon.stop()

    assert daemon._headless_cloud_sync_thread is None


@pytest.mark.daemon_aibom_refresh
@pytest.mark.daemon_bundle_refresh
@pytest.mark.daemon_headless_refresh
@pytest.mark.daemon_service_workers
def test_daemon_start_composes_all_background_workers(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    started: list[str] = []
    monkeypatch.setattr(
        guard_daemon_module.GuardDaemonServer,
        "_start_aibom_inventory_refresh",
        lambda _self: started.append("aibom"),
    )
    monkeypatch.setattr(
        guard_daemon_module.GuardDaemonServer,
        "_start_supply_chain_bundle_refresh",
        lambda _self: started.append("bundle"),
    )
    monkeypatch.setattr(
        guard_daemon_module.GuardDaemonServer,
        "_start_headless_cloud_sync",
        lambda _self: started.append("headless"),
    )
    monkeypatch.setattr(
        guard_daemon_module,
        "start_command_queue_worker",
        lambda _store, existing: started.append("command-queue") or existing,
    )
    monkeypatch.setattr(
        guard_daemon_module,
        "start_cloud_sync_sync_worker",
        lambda _store, existing: started.append("live-request-sync") or existing,
    )
    daemon = guard_daemon_module.GuardDaemonServer(
        GuardStore(tmp_path / "guard-home"),
        host="127.0.0.1",
        port=0,
        idle_timeout_seconds=60,
    )

    daemon.start()
    try:
        assert started == ["headless", "bundle", "aibom", "command-queue", "live-request-sync"]
    finally:
        daemon.stop()


def test_unmarked_daemon_does_not_start_background_workers(tmp_path: Path) -> None:
    daemon = guard_daemon_module.GuardDaemonServer(
        GuardStore(tmp_path / "guard-home"),
        host="127.0.0.1",
        port=0,
        idle_timeout_seconds=60,
    )

    daemon.start()
    try:
        assert daemon._headless_cloud_sync_thread is None
        assert daemon._bundle_refresh_thread is None
        assert daemon._aibom_refresh_thread is None
        assert daemon._command_queue_worker is None
        assert daemon._live_request_sync_worker is None
    finally:
        daemon.stop()
