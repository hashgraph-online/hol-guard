from __future__ import annotations

import argparse
import io
import json
import sqlite3
from datetime import datetime, timezone

import pytest

from codex_plugin_scanner.guard.cli import commands_router, product
from codex_plugin_scanner.guard.models import GuardReceipt
from codex_plugin_scanner.guard.store import GuardStore


def _run_status(guard_home):
    output = io.StringIO()
    result = commands_router.run_guard_command(
        argparse.Namespace(
            guard_command="desktop", desktop_command="status", guard_home=str(guard_home),
            home=str(guard_home.parent), workspace=None, source="default", json=True,
        ),
        output_stream=output,
    )
    return result, json.loads(output.getvalue()) if output.getvalue() else None


@pytest.fixture(autouse=True)
def no_daemon(monkeypatch):
    monkeypatch.setattr(product, "load_guard_daemon_endpoint_url", lambda _home: None)


def test_status_does_not_initialize_an_absent_guard_home(tmp_path):
    guard_home = tmp_path / "absent"
    result, _ = _run_status(guard_home)
    assert not guard_home.exists()
    assert result == 2


def test_status_does_not_repair_oauth_credentials(tmp_path, monkeypatch):
    guard_home = tmp_path / "guard"
    GuardStore(guard_home, prime_policy_integrity=False)

    def fail_repair(_store):
        raise AssertionError("passive status must not repair OAuth credentials")

    monkeypatch.setattr(GuardStore, "repair_oauth_local_credential_storage_from_primary", fail_repair)
    result, payload = _run_status(guard_home)
    assert result == 0
    assert payload["cloud"]["status"] == "not_connected"


def test_status_does_not_backfill_receipt_rollups_and_counts_beyond_preview(tmp_path):
    guard_home = tmp_path / "guard"
    store = GuardStore(guard_home, prime_policy_integrity=False)
    now = datetime.now(timezone.utc).isoformat()
    for index in range(25):
        store.add_receipt(GuardReceipt(
            receipt_id=f"receipt-{index}", harness="codex", artifact_id="artifact",
            artifact_hash="hash", policy_decision="block" if index < 23 else "allow",
            capabilities_summary="synthetic", changed_capabilities=(), provenance_summary="synthetic",
            timestamp=now,
        ))
    with store._connect() as connection:
        connection.execute("delete from receipt_rollup_actions")
    result, payload = _run_status(guard_home)
    with store._connect() as connection:
        assert connection.execute("select count(*) from receipt_rollup_actions").fetchone()[0] == 0
    assert result == 0
    assert len(payload["recentReceipts"]) == 20
    assert payload["receipts"]["blockedToday"] == 23
    assert payload["receipts"]["approvedToday"] == 2


def test_status_rejects_dashboard_availability_without_authenticated_endpoint(tmp_path, monkeypatch):
    from codex_plugin_scanner.guard.daemon import manager, runtime_peer

    guard_home = tmp_path / "guard"
    GuardStore(guard_home, prime_policy_integrity=False)
    monkeypatch.setattr(product, "load_guard_daemon_endpoint_url", runtime_peer.load_guard_daemon_endpoint_url)
    monkeypatch.setattr(manager, "load_guard_daemon_url", lambda _home: "http://127.0.0.1:43123")
    monkeypatch.setattr(manager, "load_guard_daemon_auth_token", lambda _home: None)
    monkeypatch.setattr(runtime_peer, "live_desktop_owned_daemon", lambda _home: None)
    result, payload = _run_status(guard_home)
    assert result == 0
    assert payload["dashboard"]["available"] is False
    assert payload["daemon"]["running"] is False
    assert "sessionUrl" not in payload["dashboard"]


def test_status_sqlite_connection_rejects_accidental_writes(tmp_path):
    from codex_plugin_scanner.guard.cli.desktop_status_store import DesktopStatusStore

    GuardStore(tmp_path, prime_policy_integrity=False)
    reader = DesktopStatusStore(tmp_path)
    try:
        with reader._connect() as connection, pytest.raises(sqlite3.OperationalError, match="readonly"):
            connection.execute("delete from guard_devices")
    finally:
        reader.close()


def test_status_keeps_one_workspace_snapshot_when_another_connection_switches_account(tmp_path):
    from codex_plugin_scanner.guard.cli.desktop_status_store import DesktopStatusStore

    store = GuardStore(tmp_path, prime_policy_integrity=False)
    with store._connect() as connection:
        connection.execute("pragma journal_mode=wal")
    store.set_sync_payload("oauth_local_credentials", {"workspace_id": "workspace-A"}, "2026-09-17T00:00:00Z")
    reader = DesktopStatusStore(tmp_path)
    try:
        assert reader.get_cloud_workspace_id() == "workspace-A"
        store.set_sync_payload("oauth_local_credentials", {"workspace_id": "workspace-B"}, "2026-09-17T00:00:01Z")
        assert reader.get_cloud_workspace_id() == "workspace-A"
    finally:
        reader.close()
    later = DesktopStatusStore(tmp_path)
    try:
        assert later.get_cloud_workspace_id() == "workspace-B"
    finally:
        later.close()


def test_status_reads_existing_oauth_vault_without_promotion_or_secret_echo(tmp_path):
    from hashlib import sha256

    from codex_plugin_scanner.guard.cli.desktop_status_store import DesktopStatusStore
    from codex_plugin_scanner.guard.store_base import EncryptedFileSecretStore

    store = GuardStore(tmp_path, prime_policy_integrity=False)
    secret_ref = "synthetic-desktop-status"
    secret_text = json.dumps({
        "refresh_token": "private-refresh-canary", "dpop_private_key_pem": "private-dpop-canary",
        "dpop_public_jwk": {"kty": "EC"}, "dpop_public_jwk_thumbprint": "synthetic-thumbprint",
    })
    EncryptedFileSecretStore(tmp_path).set_secret(secret_ref, secret_text)
    store.set_sync_payload("oauth_local_credentials", {
        "issuer": "https://hol.org", "client_id": "hol-guard", "workspace_id": "synthetic-workspace",
        "credentials_ref": secret_ref, "credentials_sha256": sha256(secret_text.encode()).hexdigest(),
    }, "2026-09-17T00:00:00Z")
    before = {path.name: path.read_bytes() for path in (tmp_path / "secrets").iterdir() if path.is_file()}
    reader = DesktopStatusStore(tmp_path)
    try:
        assert reader.get_oauth_local_credential_health() == {"configured": True, "state": "healthy"}
        assert reader.get_cloud_sync_profile()["workspace_id"] == "synthetic-workspace"
    finally:
        reader.close()
    result, payload = _run_status(tmp_path)
    assert result == 0
    assert "private-refresh-canary" not in json.dumps(payload)
    assert "private-dpop-canary" not in json.dumps(payload)
    assert before == {path.name: path.read_bytes() for path in (tmp_path / "secrets").iterdir() if path.is_file()}


def test_status_projects_dirty_receipt_actions_without_reconciling_them(tmp_path):
    store = GuardStore(tmp_path, prime_policy_integrity=False)
    store.add_receipt(GuardReceipt(
        receipt_id="dirty-receipt", harness="codex", artifact_id="artifact", artifact_hash="hash",
        policy_decision="allow", capabilities_summary="synthetic", changed_capabilities=(),
        provenance_summary="synthetic", timestamp=datetime.now(timezone.utc).isoformat(),
    ))
    with store._connect() as connection:
        connection.execute("update runtime_receipts set policy_decision = 'block' where receipt_id = 'dirty-receipt'")
        assert connection.execute("select dirty from receipt_rollup_actions").fetchone()[0] == 1
    result, payload = _run_status(tmp_path)
    assert result == 0
    assert payload["receipts"]["blockedToday"] == 1
    assert payload["receipts"]["approvedToday"] == 0
    with store._connect() as connection:
        row = connection.execute("select dirty, policy_decision from receipt_rollup_actions").fetchone()
        assert tuple(row) == (1, "allow")


def test_status_does_not_recover_a_damaged_database(tmp_path):
    tmp_path.joinpath("guard.db").write_bytes(b"damaged synthetic sqlite fixture")
    before = {path.name: path.read_bytes() for path in tmp_path.iterdir() if path.is_file()}
    result, _ = _run_status(tmp_path)
    assert result == 2
    assert before == {path.name: path.read_bytes() for path in tmp_path.iterdir() if path.is_file()}
