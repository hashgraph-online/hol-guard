"""Tests for HOL Guard daemon supply-chain intel refresh."""

from __future__ import annotations

import time
from pathlib import Path

from codex_plugin_scanner.guard.daemon import server as guard_daemon_module
from codex_plugin_scanner.guard.runtime.runner import GuardSyncAuthorizationExpiredError, GuardSyncNotConfiguredError
from codex_plugin_scanner.guard.store import GuardStore


def test_daemon_refreshes_supply_chain_bundle_on_start_and_interval(
    tmp_path: Path,
    monkeypatch,
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    store.set_sync_credentials(
        "https://hol.org/api/guard/receipts/sync",
        "demo-token",
        "2026-05-19T00:00:00Z",
        workspace_id="workspace-alpha",
    )
    calls: list[float] = []

    def _fake_sync(_store: GuardStore) -> dict[str, object]:
        calls.append(time.monotonic())
        return {
            "status": "synced",
            "bundle_version": f"1747612800000-refresh-{len(calls)}",
            "workspace_id": "workspace-alpha",
        }

    monkeypatch.setattr(guard_daemon_module, "sync_supply_chain_bundle", _fake_sync)
    daemon = guard_daemon_module.GuardDaemonServer(
        store,
        host="127.0.0.1",
        port=0,
        idle_timeout_seconds=60,
        bundle_refresh_interval_seconds=0.05,
        bundle_refresh_backoff_seconds=0.05,
    )
    daemon.start()
    try:
        deadline = time.time() + 1
        while len(calls) < 2 and time.time() < deadline:
            time.sleep(0.02)
    finally:
        daemon.stop()

    assert len(calls) >= 2
    summary = store.get_sync_payload("supply_chain_bundle_daemon")
    assert isinstance(summary, dict)
    assert summary["status"] == "synced"
    assert summary["workspace_id"] == "workspace-alpha"


def test_daemon_bundle_refresh_stays_quiet_when_not_configured(
    tmp_path: Path,
    monkeypatch,
) -> None:
    store = GuardStore(tmp_path / "guard-home")

    def _fail_sync(_store: GuardStore) -> dict[str, object]:
        raise GuardSyncNotConfiguredError("Guard is not logged in.")

    monkeypatch.setattr(guard_daemon_module, "sync_supply_chain_bundle", _fail_sync)
    daemon = guard_daemon_module.GuardDaemonServer(
        store,
        host="127.0.0.1",
        port=0,
        idle_timeout_seconds=60,
        bundle_refresh_interval_seconds=0.05,
        bundle_refresh_backoff_seconds=0.05,
    )
    daemon.start()
    try:
        time.sleep(0.12)
    finally:
        daemon.stop()

    summary = store.get_sync_payload("supply_chain_bundle_daemon")
    assert isinstance(summary, dict)
    assert summary["status"] == "not_configured"
    assert store.list_approval_requests() == []
    assert store.list_events(limit=5) == []


def test_daemon_bundle_refresh_reports_auth_expired(
    tmp_path: Path,
    monkeypatch,
) -> None:
    store = GuardStore(tmp_path / "guard-home")

    def _fail_sync(_store: GuardStore) -> dict[str, object]:
        raise GuardSyncAuthorizationExpiredError(
            "Guard authorization expired. Run `hol-guard connect` to sign in again."
        )

    monkeypatch.setattr(guard_daemon_module, "sync_supply_chain_bundle", _fail_sync)
    daemon = guard_daemon_module.GuardDaemonServer(
        store,
        host="127.0.0.1",
        port=0,
        idle_timeout_seconds=60,
        bundle_refresh_interval_seconds=0.05,
        bundle_refresh_backoff_seconds=0.05,
    )
    daemon.start()
    try:
        time.sleep(0.12)
    finally:
        daemon.stop()

    summary = store.get_sync_payload("supply_chain_bundle_daemon")
    assert isinstance(summary, dict)
    assert summary["status"] == "auth_expired"
    assert "hol-guard connect" in str(summary["message"])
