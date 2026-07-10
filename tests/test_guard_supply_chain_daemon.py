"""Tests for HOL Guard daemon supply-chain intel refresh."""

from __future__ import annotations

import threading
import time
from pathlib import Path

import pytest

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


def _wait_for_aibom_status(store, *, expected: str, timeout: float = 5.0) -> dict[str, object]:
    """Poll until the AIBOM daemon payload carries the expected status string."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        payload = store.get_sync_payload("aibom_inventory_daemon")
        if isinstance(payload, dict) and payload.get("status") == expected:
            return payload
        time.sleep(0.02)
    payload = store.get_sync_payload("aibom_inventory_daemon")
    assert isinstance(payload, dict), f"aibom_inventory_daemon payload missing: {payload!r}"
    assert payload.get("status") == expected, f"expected status={expected!r}, got {payload!r}"
    return payload


def test_daemon_aibom_refresh_records_synced_on_success(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """AIBOM refresh loop stores aibom_inventory_daemon with status=synced on success."""
    store = GuardStore(tmp_path / "guard-home")
    _seed_guard_cloud(store, workspace_id="workspace-alpha")
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    calls: list[dict[str, object]] = []

    def _fake_sync(_store: GuardStore, **kwargs: object) -> dict[str, object]:
        calls.append(kwargs)
        return {"synced": True, "synced_at": "2026-06-29T00:00:00Z", "snapshots": 2, "accepted": 2}

    monkeypatch.setattr(guard_daemon_module, "sync_aibom_snapshots_if_due", _fake_sync)
    daemon = guard_daemon_module.GuardDaemonServer(
        store,
        host="127.0.0.1",
        port=0,
        idle_timeout_seconds=60,
        aibom_refresh_interval_seconds=60,
        aibom_refresh_backoff_seconds=0.05,
        home_dir=home_dir,
        workspace_dir=workspace_dir,
    )
    daemon.start()
    try:
        _wait_for_aibom_status(store, expected="synced")
    finally:
        daemon.stop()

    assert calls
    assert calls[0]["home_dir"] == home_dir
    assert calls[0]["workspace_dir"] == workspace_dir
    summary = store.get_sync_payload("aibom_inventory_daemon")
    assert isinstance(summary, dict)
    assert summary["status"] == "synced"
    assert summary["synced"] is True
    assert summary["snapshots"] == 2


def test_daemon_aibom_refresh_records_skipped_when_not_due(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """AIBOM refresh loop stores status derived from reason when sync returns synced=False."""
    store = GuardStore(tmp_path / "guard-home")
    _seed_guard_cloud(store, workspace_id="workspace-alpha")

    def _fake_sync(_store: GuardStore, **_kwargs: object) -> dict[str, object]:
        return {"synced": False, "reason": "not_due", "skipped": True}

    monkeypatch.setattr(guard_daemon_module, "sync_aibom_snapshots_if_due", _fake_sync)
    daemon = guard_daemon_module.GuardDaemonServer(
        store,
        host="127.0.0.1",
        port=0,
        idle_timeout_seconds=60,
        aibom_refresh_interval_seconds=0.05,
        aibom_refresh_backoff_seconds=0.05,
        workspace_dir=tmp_path / "workspace",
    )
    daemon.start()
    try:
        _wait_for_aibom_status(store, expected="not_due")
    finally:
        daemon.stop()

    summary = store.get_sync_payload("aibom_inventory_daemon")
    assert isinstance(summary, dict)
    assert summary["status"] == "not_due"
    assert summary["synced"] is False
    assert summary["skipped"] is True


def test_daemon_aibom_refresh_resolves_managed_workspace_context(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """AIBOM daemon resolves an audited workspace before publishing inventory."""
    store = GuardStore(tmp_path / "guard-home")
    _seed_guard_cloud(store, workspace_id="workspace-alpha")
    calls: list[dict[str, object]] = []

    def _fake_sync(_store: GuardStore, **kwargs: object) -> dict[str, object]:
        calls.append(kwargs)
        return {"synced": True, "synced_at": "2026-06-29T00:00:00Z", "snapshots": 1, "accepted": 1}

    monkeypatch.setattr(guard_daemon_module, "sync_aibom_snapshots_if_due", _fake_sync)
    resolved_workspace = tmp_path / "managed-workspace"
    monkeypatch.setattr(
        guard_daemon_module,
        "resolve_supply_chain_audit_workspace_dir",
        lambda **_kwargs: resolved_workspace,
    )
    daemon = guard_daemon_module.GuardDaemonServer(
        store,
        host="127.0.0.1",
        port=0,
        idle_timeout_seconds=60,
        aibom_refresh_interval_seconds=60,
        aibom_refresh_backoff_seconds=0.05,
    )
    daemon.start()
    try:
        summary = _wait_for_aibom_status(store, expected="synced")
    finally:
        daemon.stop()

    assert calls[0]["home_dir"] is None
    assert calls[0]["workspace_dir"] == resolved_workspace
    assert summary["synced"] is True


def test_daemon_aibom_refresh_skips_without_workspace_context(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """AIBOM daemon does not replace a full snapshot with a home-only scan."""
    store = GuardStore(tmp_path / "guard-home")
    _seed_guard_cloud(store, workspace_id="workspace-alpha")
    calls: list[dict[str, object]] = []

    monkeypatch.setattr(
        guard_daemon_module,
        "sync_aibom_snapshots_if_due",
        lambda _store, **kwargs: calls.append(kwargs) or {"synced": True},
    )
    monkeypatch.setattr(
        guard_daemon_module,
        "resolve_supply_chain_audit_workspace_dir",
        lambda **_kwargs: None,
    )
    daemon = guard_daemon_module.GuardDaemonServer(
        store,
        host="127.0.0.1",
        port=0,
        idle_timeout_seconds=60,
        aibom_refresh_interval_seconds=60,
        aibom_refresh_backoff_seconds=0.05,
    )
    daemon.start()
    try:
        summary = _wait_for_aibom_status(store, expected="missing_workspace_context")
    finally:
        daemon.stop()

    assert calls == []
    assert summary["reason"] == "missing_workspace_context"


def test_daemon_aibom_refresh_retries_returned_error_on_backoff(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """Returned sync errors retry on backoff instead of waiting for the normal interval."""
    store = GuardStore(tmp_path / "guard-home")
    _seed_guard_cloud(store, workspace_id="workspace-alpha")
    calls = 0

    def _fake_sync(_store: GuardStore, **_kwargs: object) -> dict[str, object]:
        nonlocal calls
        calls += 1
        if calls == 1:
            return {"synced": False, "error": "temporary upload failure"}
        return {"synced": True, "snapshots": 2, "accepted": 2}

    monkeypatch.setattr(guard_daemon_module, "sync_aibom_snapshots_if_due", _fake_sync)
    daemon = guard_daemon_module.GuardDaemonServer(
        store,
        host="127.0.0.1",
        port=0,
        idle_timeout_seconds=60,
        aibom_refresh_interval_seconds=60,
        aibom_refresh_backoff_seconds=0.05,
        workspace_dir=tmp_path / "workspace",
    )
    daemon.start()
    try:
        summary = _wait_for_aibom_status(store, expected="synced")
    finally:
        daemon.stop()

    assert calls == 2
    assert summary["synced"] is True


def test_daemon_aibom_refresh_records_error_on_exception(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """AIBOM refresh loop stores status=error when sync_aibom_snapshots_if_due raises."""
    store = GuardStore(tmp_path / "guard-home")
    _seed_guard_cloud(store, workspace_id="workspace-alpha")

    def _fail_sync(_store: GuardStore, **_kwargs: object) -> dict[str, object]:
        raise RuntimeError("AIBOM snapshot upload failed: mirror node timeout")

    monkeypatch.setattr(guard_daemon_module, "sync_aibom_snapshots_if_due", _fail_sync)
    daemon = guard_daemon_module.GuardDaemonServer(
        store,
        host="127.0.0.1",
        port=0,
        idle_timeout_seconds=60,
        aibom_refresh_interval_seconds=0.05,
        aibom_refresh_backoff_seconds=0.05,
        workspace_dir=tmp_path / "workspace",
    )
    daemon.start()
    try:
        _wait_for_aibom_status(store, expected="error")
    finally:
        daemon.stop()

    summary = store.get_sync_payload("aibom_inventory_daemon")
    assert isinstance(summary, dict)
    assert summary["status"] == "error"
    assert "mirror node timeout" in str(summary["error"])


def test_daemon_aibom_refresh_stops_cleanly(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """Daemon.stop() joins the AIBOM refresh thread within timeout."""
    store = GuardStore(tmp_path / "guard-home")
    _seed_guard_cloud(store, workspace_id="workspace-alpha")

    monkeypatch.setattr(
        guard_daemon_module,
        "sync_aibom_snapshots_if_due",
        lambda _store, **_kwargs: {"synced": True, "synced_at": "2026-06-29T00:00:00Z"},
    )
    daemon = guard_daemon_module.GuardDaemonServer(
        store,
        host="127.0.0.1",
        port=0,
        idle_timeout_seconds=60,
        aibom_refresh_interval_seconds=0.05,
        aibom_refresh_backoff_seconds=0.05,
        workspace_dir=tmp_path / "workspace",
    )
    daemon.start()
    # Let at least one refresh cycle run
    _wait_for_aibom_status(store, expected="synced")

    daemon.stop()

    # Thread reference is cleared and no longer alive after stop
    assert daemon._aibom_refresh_thread is None


def test_daemon_retains_blocked_aibom_refresh_thread_during_shutdown(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """A blocked refresh remains tracked and prevents a concurrent daemon restart."""
    store = GuardStore(tmp_path / "guard-home")
    _seed_guard_cloud(store, workspace_id="workspace-alpha")
    entered = threading.Event()
    release = threading.Event()

    def _blocked_sync(_store: GuardStore, **_kwargs: object) -> dict[str, object]:
        entered.set()
        release.wait(timeout=5)
        return {"synced": True}

    monkeypatch.setattr(guard_daemon_module, "sync_aibom_snapshots_if_due", _blocked_sync)
    monkeypatch.setattr(guard_daemon_module, "_AIBOM_REFRESH_STOP_JOIN_TIMEOUT_SECONDS", 0.01)
    daemon = guard_daemon_module.GuardDaemonServer(
        store,
        host="127.0.0.1",
        port=0,
        idle_timeout_seconds=60,
        aibom_refresh_interval_seconds=60,
        workspace_dir=tmp_path / "workspace",
    )
    daemon.start()
    assert entered.wait(timeout=1)

    daemon.stop()
    refresh_thread = daemon._aibom_refresh_thread
    assert refresh_thread is not None
    assert refresh_thread.is_alive()
    with pytest.raises(RuntimeError, match="still stopping"):
        daemon.start()

    release.set()
    refresh_thread.join(timeout=1)
    assert not refresh_thread.is_alive()
