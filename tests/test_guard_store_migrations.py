"""Tests for Guard store migration-safe schema and credential handling."""

from __future__ import annotations

import json
import sqlite3

from codex_plugin_scanner.guard.store import GuardStore


def test_sync_credentials_are_not_persisted_in_plaintext_sqlite(tmp_path):
    store = GuardStore(tmp_path / "guard-home")
    store.set_sync_credentials(
        "https://hol.org/api/guard/receipts/sync",
        "secret-token-value",
        "2026-04-19T00:00:00+00:00",
    )

    with sqlite3.connect(store.path) as connection:
        row = connection.execute(
            "select payload_json from sync_state where state_key = 'credentials'"
        ).fetchone()

    assert row is not None
    payload = json.loads(str(row[0]))
    assert payload["sync_url"] == "https://hol.org/api/guard/receipts/sync"
    assert payload.get("token_ref") == "guard-cloud-token"
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
        row = connection.execute(
            "select payload_json from sync_state where state_key = 'credentials'"
        ).fetchone()

    payload = json.loads(str(row[0])) if row is not None else {}
    assert "token" not in payload
    assert payload.get("token_ref") == "guard-cloud-token"


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
