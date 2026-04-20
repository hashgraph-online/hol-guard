"""Tests for Guard store migration-safe schema and credential handling."""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import subprocess

from codex_plugin_scanner.guard.store import (
    EncryptedFileSecretStore,
    FallbackSecretStore,
    GuardStore,
    KeychainSecretStore,
    _build_secret_store,
)


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
    assert isinstance(payload.get("token_ref"), str)
    assert str(payload["token_ref"]).startswith("guard-cloud-token:")
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
    assert isinstance(payload.get("token_ref"), str)
    assert str(payload["token_ref"]).startswith("guard-cloud-token:")
    assert isinstance(payload.get("token_sha256"), str)


def test_sync_credentials_are_scoped_per_guard_home(tmp_path):
    home_a = tmp_path / "guard-home-a"
    home_b = tmp_path / "guard-home-b"
    store_a = GuardStore(home_a)
    store_b = GuardStore(home_b)

    store_a.set_sync_credentials(
        "https://hol.org/api/guard/receipts/sync",
        "token-a",
        "2026-04-19T00:00:00+00:00",
    )
    store_b.set_sync_credentials(
        "https://hol.org/api/guard/receipts/sync",
        "token-b",
        "2026-04-19T00:00:05+00:00",
    )

    assert store_a.get_sync_credentials() == {
        "sync_url": "https://hol.org/api/guard/receipts/sync",
        "token": "token-a",
    }
    assert store_b.get_sync_credentials() == {
        "sync_url": "https://hol.org/api/guard/receipts/sync",
        "token": "token-b",
    }


def test_legacy_token_reference_is_migrated_to_scoped_reference(tmp_path):
    store = GuardStore(tmp_path / "guard-home")
    legacy_token = "legacy-token-ref"
    legacy_ref = "guard-cloud-token"
    store._secret_store.set_secret(legacy_ref, legacy_token)
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
                        "token_ref": legacy_ref,
                        "token_sha256": hashlib.sha256(legacy_token.encode("utf-8")).hexdigest(),
                    }
                ),
                "2026-04-19T00:00:00+00:00",
            ),
        )

    credentials = store.get_sync_credentials()
    assert credentials == {
        "sync_url": "https://hol.org/api/guard/receipts/sync",
        "token": legacy_token,
    }
    assert store._secret_store.get_secret(store._sync_token_ref) == legacy_token

    with sqlite3.connect(store.path) as connection:
        row = connection.execute("select payload_json from sync_state where state_key = 'credentials'").fetchone()
    payload = json.loads(str(row[0])) if row is not None else {}
    assert payload["token_ref"] == store._sync_token_ref


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


def test_fallback_secret_store_promotes_secret_to_primary():
    class MemoryStore:
        def __init__(self) -> None:
            self._data: dict[str, str] = {}

        def set_secret(self, secret_id: str, value: str) -> None:
            self._data[secret_id] = value

        def get_secret(self, secret_id: str) -> str | None:
            return self._data.get(secret_id)

    primary = MemoryStore()
    fallback = MemoryStore()
    fallback.set_secret("guard-token", "value-123")

    store = FallbackSecretStore(primary, fallback)

    assert store.get_secret("guard-token") == "value-123"
    assert primary.get_secret("guard-token") is None

    store.promote_secret("guard-token", "value-123")

    assert primary.get_secret("guard-token") == "value-123"


def test_secret_store_prefers_encrypted_file_backend_when_keychain_is_available(tmp_path, monkeypatch):
    guard_home = tmp_path / "guard-home"
    monkeypatch.setattr(KeychainSecretStore, "_is_available", staticmethod(lambda: True))

    secret_store = _build_secret_store(guard_home)

    assert isinstance(secret_store, FallbackSecretStore)
    assert isinstance(secret_store.primary, EncryptedFileSecretStore)
    assert isinstance(secret_store.fallback, KeychainSecretStore)


def test_encrypted_file_secret_store_secures_secret_directory_permissions(tmp_path):
    secret_store = EncryptedFileSecretStore(tmp_path / "guard-home")

    secret_store.set_secret("guard-token", "value-123")

    assert secret_store.base_dir.stat().st_mode & 0o777 == 0o700
    assert secret_store.key_path.stat().st_mode & 0o777 == 0o600
    assert secret_store._path_for("guard-token").stat().st_mode & 0o777 == 0o600


def test_encrypted_file_secret_store_writes_key_and_payload_atomically(tmp_path, monkeypatch):
    secret_store = EncryptedFileSecretStore(tmp_path / "guard-home")
    recorded_replacements: list[tuple[str, str]] = []
    original_replace = os.replace

    def tracking_replace(src: str | os.PathLike[str], dst: str | os.PathLike[str]) -> None:
        recorded_replacements.append((os.fspath(src), os.fspath(dst)))
        original_replace(src, dst)

    monkeypatch.setattr(os, "replace", tracking_replace)

    secret_store.set_secret("guard-token", "value-123")

    assert any(dst.endswith("key.bin") for _, dst in recorded_replacements)
    assert any(dst.endswith("guard-token.enc") for _, dst in recorded_replacements)


def test_sync_credentials_do_not_shell_out_to_keychain_when_file_store_is_available(tmp_path, monkeypatch):
    guard_home = tmp_path / "guard-home"
    monkeypatch.setattr(KeychainSecretStore, "_is_available", staticmethod(lambda: True))

    def fail_on_keychain(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        raise AssertionError("keychain should not be used for sync credential writes")

    monkeypatch.setattr(subprocess, "run", fail_on_keychain)
    store = GuardStore(guard_home)

    store.set_sync_credentials(
        "https://hol.org/api/guard/receipts/sync",
        "secret-token-value",
        "2026-04-19T00:00:00+00:00",
    )

    assert store.get_sync_credentials() == {
        "sync_url": "https://hol.org/api/guard/receipts/sync",
        "token": "secret-token-value",
    }
    assert any((guard_home / "secrets").glob("*.enc"))


def test_validated_keychain_fallback_reads_are_migrated_into_encrypted_file_store(tmp_path, monkeypatch):
    guard_home = tmp_path / "guard-home"
    monkeypatch.setattr(KeychainSecretStore, "_is_available", staticmethod(lambda: True))

    keychain_reads = 0

    def keychain_lookup(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        nonlocal keychain_reads
        keychain_reads += 1
        return subprocess.CompletedProcess(
            args=["/usr/bin/security"],
            returncode=0,
            stdout="legacy-token\n",
            stderr="",
        )

    monkeypatch.setattr(subprocess, "run", keychain_lookup)
    store = GuardStore(guard_home)

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
                        "token_ref": store._sync_token_ref,
                        "token_sha256": hashlib.sha256(b"legacy-token").hexdigest(),
                    }
                ),
                "2026-04-19T00:00:00+00:00",
            ),
        )

    assert store.get_sync_credentials() == {
        "sync_url": "https://hol.org/api/guard/receipts/sync",
        "token": "legacy-token",
    }
    assert keychain_reads == 1
    assert any((guard_home / "secrets").glob("*.enc"))

    def fail_on_keychain(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        raise AssertionError("fallback keychain should not be used after migration")

    monkeypatch.setattr(subprocess, "run", fail_on_keychain)

    assert store.get_sync_credentials() == {
        "sync_url": "https://hol.org/api/guard/receipts/sync",
        "token": "legacy-token",
    }


def test_invalid_keychain_fallback_token_is_not_migrated_into_encrypted_file_store(tmp_path, monkeypatch):
    guard_home = tmp_path / "guard-home"
    monkeypatch.setattr(KeychainSecretStore, "_is_available", staticmethod(lambda: True))

    keychain_reads = 0

    def keychain_lookup(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        nonlocal keychain_reads
        keychain_reads += 1
        return subprocess.CompletedProcess(
            args=["/usr/bin/security"],
            returncode=0,
            stdout="stale-token\n",
            stderr="",
        )

    monkeypatch.setattr(subprocess, "run", keychain_lookup)
    store = GuardStore(guard_home)

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
                        "token_ref": store._sync_token_ref,
                        "token_sha256": hashlib.sha256(b"fresh-token").hexdigest(),
                    }
                ),
                "2026-04-19T00:00:00+00:00",
            ),
        )

    assert store.get_sync_credentials() is None
    assert keychain_reads == 1
    assert list((guard_home / "secrets").glob("*.enc")) == []

    assert store.get_sync_credentials() is None
    assert keychain_reads == 2
    assert list((guard_home / "secrets").glob("*.enc")) == []


def test_stale_file_token_does_not_block_valid_keychain_token_migration(tmp_path, monkeypatch):
    guard_home = tmp_path / "guard-home"
    monkeypatch.setattr(KeychainSecretStore, "_is_available", staticmethod(lambda: True))

    keychain_reads = 0

    def keychain_lookup(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        nonlocal keychain_reads
        keychain_reads += 1
        return subprocess.CompletedProcess(
            args=["/usr/bin/security"],
            returncode=0,
            stdout="fresh-token\n",
            stderr="",
        )

    monkeypatch.setattr(subprocess, "run", keychain_lookup)
    store = GuardStore(guard_home)
    store._secret_store.set_secret(store._sync_token_ref, "stale-token")

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
                        "token_ref": store._sync_token_ref,
                        "token_sha256": hashlib.sha256(b"fresh-token").hexdigest(),
                    }
                ),
                "2026-04-19T00:00:00+00:00",
            ),
        )

    assert store.get_sync_credentials() == {
        "sync_url": "https://hol.org/api/guard/receipts/sync",
        "token": "fresh-token",
    }
    assert keychain_reads == 1
    assert store._secret_store.get_secret(store._sync_token_ref) == "fresh-token"


def test_valid_file_token_does_not_query_keychain_fallback(tmp_path, monkeypatch):
    guard_home = tmp_path / "guard-home"
    monkeypatch.setattr(KeychainSecretStore, "_is_available", staticmethod(lambda: True))

    def fail_on_keychain(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        raise AssertionError("keychain fallback should not run when file secret is valid")

    monkeypatch.setattr(subprocess, "run", fail_on_keychain)
    store = GuardStore(guard_home)
    store._secret_store.set_secret(store._sync_token_ref, "fresh-token")

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
                        "token_ref": store._sync_token_ref,
                        "token_sha256": hashlib.sha256(b"fresh-token").hexdigest(),
                    }
                ),
                "2026-04-19T00:00:00+00:00",
            ),
        )

    assert store.get_sync_credentials() == {
        "sync_url": "https://hol.org/api/guard/receipts/sync",
        "token": "fresh-token",
    }


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
