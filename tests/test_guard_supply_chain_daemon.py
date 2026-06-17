"""Tests for HOL Guard daemon supply-chain intel refresh."""

from __future__ import annotations

import time
from pathlib import Path

from codex_plugin_scanner.guard.daemon import server as guard_daemon_module
from codex_plugin_scanner.guard.runtime.runner import GuardSyncAuthorizationExpiredError, GuardSyncNotConfiguredError
from codex_plugin_scanner.guard.store import GuardStore


def _seed_guard_cloud(store, *, workspace_id=None, sync_url=None, token="demo-token", now="2026-05-19T00:00:00Z"):
    """Seed OAuth credentials (replaces legacy set_sync_credentials scaffolding).

    Also installs a test-only resolver override so sync-path exercises stay hermetic
    (no OAuth token refresh against the network). Tests that need real sync against a
    local server pass sync_url=<url>.
    """
    from codex_plugin_scanner.guard.cli.oauth_client import generate_dpop_key_pair
    from codex_plugin_scanner.guard.runtime import runner as guard_runner_module

    dpop_key_material = generate_dpop_key_pair()
    store.set_oauth_local_credentials(
        issuer="https://hol.org",
        client_id="guard-local-daemon",
        refresh_token=token,
        dpop_private_key_pem=dpop_key_material.private_key_pem,
        dpop_public_jwk=dpop_key_material.public_jwk,
        dpop_public_jwk_thumbprint=dpop_key_material.public_jwk_thumbprint,
        grant_id="grant-1",
        machine_id="machine-1",
        workspace_id=workspace_id,
        now=now,
    )
    effective_sync_url = sync_url if sync_url is not None else "https://hol.org/api/guard/receipts/sync"
    guard_runner_module._test_sync_auth_context_override = {
        "sync_url": effective_sync_url,
        "access_token": token,
        "dpop_key_material": None,
    }


def test_daemon_refreshes_supply_chain_bundle_on_start_and_interval(
    tmp_path: Path,
    monkeypatch,
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    _seed_guard_cloud(store, workspace_id="workspace-alpha")
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

    def _fail_sync(_store: GuardStore, **_kwargs: object) -> dict[str, object]:
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

    def _fail_sync(_store: GuardStore, **_kwargs: object) -> dict[str, object]:
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


def test_daemon_bundle_refresh_reports_retryable_error(
    tmp_path: Path,
    monkeypatch,
) -> None:
    store = GuardStore(tmp_path / "guard-home")

    def _fail_sync(_store: GuardStore, **_kwargs: object) -> dict[str, object]:
        raise RuntimeError("Guard OAuth token refresh failed: oauth upstream down")

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
    assert summary["status"] == "error"
    assert "oauth upstream down" in str(summary["error"])
