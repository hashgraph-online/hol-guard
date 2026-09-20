"""Passive status cannot repair OAuth, migrate a vault or create identity."""

from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.daemon.cloud_review_settings import cloud_review_settings_status
from codex_plugin_scanner.guard.runtime.exact_cloud_review import enable_exact_cloud_review
from codex_plugin_scanner.guard.store_base import EncryptedFileSecretStore, FallbackSecretStore, _expand_keystream
from tests.guard_exact_cloud_review_support import connected_exact_review_store
from tests.test_cloud_review_status_parity import _cli_status


def _files(root: Path):
    return {
        str(path.relative_to(root)): (path.read_bytes(), path.stat().st_mode)
        for path in root.rglob("*")
        if path.is_file() and path.name not in {"guard.db", "guard.db-wal", "guard.db-shm"}
    }


def _snapshot(store):
    with store._connect() as connection:
        return tuple(connection.iterdump()), _files(store.guard_home)


def _both(store, capsys):
    return _cli_status(store, capsys), cloud_review_settings_status(store)


def test_status_does_not_restore_missing_oauth_metadata_from_existing_secret(tmp_path, capsys):
    store = connected_exact_review_store(tmp_path)
    store.record_guard_connect_pairing_completed(
        sync_url="https://hol.org/api/guard/receipts/sync",
        allowed_origin="https://hol.org",
        now="2026-09-17T00:00:00Z",
    )
    store.delete_sync_payload("oauth_local_credentials")
    store._clear_oauth_secret_payload_cache()
    before = _snapshot(store)

    results = _both(store, capsys)

    assert _snapshot(store) == before
    assert store.get_sync_payload("oauth_local_credentials") is None
    assert all(result["connected"] is False for result in results)


def test_status_leaves_legacy_oauth_secret_for_explicit_migration(tmp_path, capsys):
    store = connected_exact_review_store(tmp_path)
    payload = store.get_sync_payload("oauth_local_credentials")
    vault = EncryptedFileSecretStore(store.guard_home)
    secret = vault.get_secret(payload["credentials_ref"])
    key = base64.urlsafe_b64decode(vault.key_path.read_bytes())
    nonce = b"legacy-status-test"
    clear = secret.encode()
    mask = _expand_keystream(key=key, nonce=nonce, length=len(clear))
    vault._path_for(payload["credentials_ref"]).write_text(
        json.dumps(
            {
                "nonce": base64.urlsafe_b64encode(nonce).decode(),
                "ciphertext": base64.urlsafe_b64encode(bytes(a ^ b for a, b in zip(clear, mask, strict=True))).decode(),
            }
        )
    )
    store._clear_oauth_secret_payload_cache()
    before = _snapshot(store)

    results = _both(store, capsys)

    assert _snapshot(store) == before
    assert all(result["connected"] is False for result in results)
    assert results[1]["diagnostics"]["oauth"]["state"] == "degraded"
    # The CLI retains its existing generic redaction for the OAuth diagnostics key.


def test_status_does_not_recreate_missing_installation_identity(tmp_path, capsys):
    store = connected_exact_review_store(tmp_path)
    enable_exact_cloud_review(store)
    with store._connect() as connection:
        connection.execute("delete from guard_devices")
    before = _snapshot(store)

    results = _both(store, capsys)

    assert _snapshot(store) == before
    assert all(result["enabled"] is False for result in results)


def test_status_does_not_promote_integrity_secret_from_primary_store(tmp_path, capsys):
    store = connected_exact_review_store(tmp_path)
    enable_exact_cloud_review(store)
    vault = EncryptedFileSecretStore(store.guard_home)
    secret_ref = store._policy_integrity_key_ref
    material = store._policy_integrity_secret_store.get_secret(secret_ref)
    primary = EncryptedFileSecretStore(tmp_path / "primary-keychain-fixture")
    primary.set_secret(secret_ref, material)
    vault.delete_secret(secret_ref)
    store._policy_integrity_secret_store = FallbackSecretStore(primary, vault)
    store._clear_policy_integrity_cache()
    before = _snapshot(store)

    results = _both(store, capsys)

    assert _snapshot(store) == before
    assert all(result["enabled"] is False for result in results)


def test_status_rejects_raw_existing_vault_key_without_upgrading_it(tmp_path, capsys):
    store = connected_exact_review_store(tmp_path)
    from cryptography.fernet import Fernet

    vault = EncryptedFileSecretStore(store.guard_home)
    metadata = store.get_sync_payload("oauth_local_credentials")
    secret_text = vault.get_secret(metadata["credentials_ref"])
    key_path = store.guard_home / "secrets" / "key.bin"
    legacy_key = b"A" * 32
    key_path.write_bytes(legacy_key)
    vault._path_for(metadata["credentials_ref"]).write_text(
        json.dumps(
            {
                "version": "fernet-v1",
                "ciphertext": Fernet(base64.urlsafe_b64encode(legacy_key)).encrypt(secret_text.encode()).decode(),
            }
        )
    )
    store._oauth_secret_store = EncryptedFileSecretStore(store.guard_home)
    store._policy_integrity_secret_store = EncryptedFileSecretStore(store.guard_home)
    store._clear_oauth_secret_payload_cache()
    store._clear_policy_integrity_cache()
    before = _snapshot(store)

    results = _both(store, capsys)

    assert _snapshot(store) == before
    assert all(result["connected"] is False for result in results)


def test_passive_status_snapshot_rejects_writes_and_retains_original_oauth_identity(tmp_path):
    import sqlite3

    from codex_plugin_scanner.guard.passive_status_store import PassiveStatusStore

    store = connected_exact_review_store(tmp_path)
    with store._connect() as connection:
        connection.execute("pragma journal_mode=wal")
    reader = PassiveStatusStore(store)
    try:
        before = reader.get_sync_payload("oauth_local_credentials")
        changed = {**before, "workspace_id": "workspace-B"}
        store.set_sync_payload("oauth_local_credentials", changed, "2026-09-17T00:00:01Z")
        assert reader.get_sync_payload("oauth_local_credentials") == before
        with reader._connect() as connection, pytest.raises(sqlite3.OperationalError, match="readonly"):
            connection.execute("delete from guard_devices")
    finally:
        reader.close()
    assert store.get_sync_payload("oauth_local_credentials")["workspace_id"] == "workspace-B"


@pytest.mark.parametrize("invalid", ["metadata_hash", "missing_vault_key", "public_secret", "symlink_secret"])
def test_passive_oauth_status_requires_the_existing_private_hash_bound_vault(tmp_path, capsys, invalid):
    store = connected_exact_review_store(tmp_path)
    enable_exact_cloud_review(store)
    metadata = store.get_sync_payload("oauth_local_credentials")
    vault = EncryptedFileSecretStore(store.guard_home)
    secret = vault._path_for(metadata["credentials_ref"])
    if invalid == "metadata_hash":
        store.set_sync_payload(
            "oauth_local_credentials", {**metadata, "credentials_sha256": "0" * 64}, "2026-09-17T00:00:00Z"
        )
    elif invalid == "missing_vault_key":
        vault.key_path.unlink()
    elif invalid == "public_secret":
        secret.chmod(0o644)
    else:
        target = secret.with_suffix(".preserved")
        secret.rename(target)
        secret.symlink_to(target)
    before = _snapshot(store)

    results = _both(store, capsys)

    assert _snapshot(store) == before
    assert all(result["connected"] is False and result["enabled"] is False for result in results)
