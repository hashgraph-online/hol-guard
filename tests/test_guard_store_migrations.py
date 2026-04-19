"""Tests for Guard store migration-safe schema and credential handling."""

from __future__ import annotations

import json
import sqlite3

from codex_plugin_scanner.guard.store import FallbackSecretStore, GuardStore


def test_sync_credentials_are_not_persisted_in_plaintext_sqlite(tmp_path):
    store = GuardStore(tmp_path / "guard-home")
    store.set_sync_credentials(
        "https://hol.org/api/guard/receipts/sync",
        "secret-token-value",
        "2026-04-19T00:00:00+00:00",
    )

    with sqlite3.connect(store.path) as connection:
        row = connection.execute("select payload_json from sync_state where state_key = 'credentials'").fetchone()

    assert row is not None
    payload = json.loads(str(row[0]))
    assert payload["sync_url"] == "https://hol.org/api/guard/receipts/sync"
    assert payload.get("token_ref") == "guard-cloud-token"
    assert isinstance(payload.get("token_sha256"), str)
    assert "token" not in payload
    assert store.get_sync_credentials() == {
        "sync_url": "https://hol.org/api/guard/receipts/sync",
        "token": "secret-token-value",
    }


def test_legacy_plaintext_sync_payload_is_migrated_on_read(tmp_path):
    store = GuardStore(tmp_path / "guard-home")
    with sqlite3.connect(store.path) as connection:
        connection.execute(
            """
            insert into sync_state (state_key, payload_json, updated_at)
            values ('credentials', ?, ?)
            on conflict(state_key) do update set payload_json = excluded.payload_json, updated_at = excluded.updated_at
            """,
            (
                json.dumps(
                    {
                        "sync_url": "https://hol.org/api/guard/receipts/sync",
                        "token": "legacy-token",
                    }
                ),
                "2026-04-19T00:00:00+00:00",
            ),
        )

    credentials = store.get_sync_credentials()
    assert credentials == {
        "sync_url": "https://hol.org/api/guard/receipts/sync",
        "token": "legacy-token",
    }

    with sqlite3.connect(store.path) as connection:
        row = connection.execute("select payload_json from sync_state where state_key = 'credentials'").fetchone()

    payload = json.loads(str(row[0])) if row is not None else {}
    assert "token" not in payload
    assert payload.get("token_ref") == "guard-cloud-token"
    assert isinstance(payload.get("token_sha256"), str)


def test_sync_token_rotation_with_same_url_clears_cloud_sync_payloads(tmp_path):
    store = GuardStore(tmp_path / "guard-home")
    store.set_sync_credentials(
        "https://hol.org/api/guard/receipts/sync",
        "first-token",
        "2026-04-19T00:00:00+00:00",
    )
    store.set_sync_payload("policy", {"mode": "enforce"}, "2026-04-19T00:01:00+00:00")
    store.set_sync_credentials(
        "https://hol.org/api/guard/receipts/sync",
        "rotated-token",
        "2026-04-19T00:02:00+00:00",
    )

    assert store.get_sync_payload("policy") is None
    assert store.get_sync_credentials() == {
        "sync_url": "https://hol.org/api/guard/receipts/sync",
        "token": "rotated-token",
    }


def test_fallback_secret_store_uses_secondary_backend_when_primary_fails():
    class FailingStore:
        def set_secret(self, secret_id: str, value: str) -> None:
            raise RuntimeError("primary unavailable")

        def get_secret(self, secret_id: str) -> str | None:
            raise RuntimeError("primary unavailable")

    class MemoryStore:
        def __init__(self) -> None:
            self._data: dict[str, str] = {}

        def set_secret(self, secret_id: str, value: str) -> None:
            self._data[secret_id] = value

        def get_secret(self, secret_id: str) -> str | None:
            return self._data.get(secret_id)

    store = FallbackSecretStore(FailingStore(), MemoryStore())
    store.set_secret("guard-token", "value-123")

    assert store.get_secret("guard-token") == "value-123"


def test_device_identity_and_label_management_are_persistent(tmp_path):
    store = GuardStore(tmp_path / "guard-home")
    original = store.get_device_metadata()
    assert original["installation_id"]
    assert original["device_label"]

    renamed = store.set_device_label("VPS - Guard Runtime", "2026-04-19T01:00:00+00:00")
    assert renamed["device_label"] == "VPS - Guard Runtime"

    rotated = store.rotate_installation_id("2026-04-19T02:00:00+00:00")
    assert rotated["device_label"] == "VPS - Guard Runtime"
    assert rotated["installation_id"] != original["installation_id"]
