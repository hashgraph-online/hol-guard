"""Tests for Guard store migration-safe schema and credential handling."""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import subprocess
import sys
import types

import pytest

from codex_plugin_scanner.guard import store as guard_store_module
from codex_plugin_scanner.guard.store import (
    EncryptedFileSecretStore,
    FallbackSecretStore,
    GuardStore,
    SystemKeyringSecretStore,
    UnavailableSecretStore,
    _build_oauth_secret_store,
)
from codex_plugin_scanner.guard.store_evidence import EvidenceRecord


class _FakeSystemKeyringModule:
    def __init__(self) -> None:
        self._secrets: dict[tuple[str, str], str] = {}
        self.fail_on_set = False
        self.get_password_calls = 0
        self.set_password_calls = 0
        self.get_password_calls_by_service: dict[str, int] = {}
        self.set_password_calls_by_service: dict[str, int] = {}

    @staticmethod
    def get_keyring():
        class _Backend:
            priority = 1

        return _Backend()

    def set_password(self, service_name: str, secret_id: str, value: str) -> None:
        if self.fail_on_set:
            raise RuntimeError("system keyring unavailable")
        self.set_password_calls += 1
        self.set_password_calls_by_service[service_name] = self.set_password_calls_by_service.get(service_name, 0) + 1
        self._secrets[(service_name, secret_id)] = value

    def get_password(self, service_name: str, secret_id: str) -> str | None:
        self.get_password_calls += 1
        self.get_password_calls_by_service[service_name] = self.get_password_calls_by_service.get(service_name, 0) + 1
        return self._secrets.get((service_name, secret_id))

    def delete_password(self, service_name: str, secret_id: str) -> None:
        self._secrets.pop((service_name, secret_id), None)


def _install_fake_system_keyring(
    monkeypatch,
    *,
    usable_macos_keychain: bool = True,
) -> _FakeSystemKeyringModule:
    module = _FakeSystemKeyringModule()
    monkeypatch.setattr(SystemKeyringSecretStore, "_load_keyring_module", staticmethod(lambda: module))
    monkeypatch.setattr(
        SystemKeyringSecretStore,
        "_macos_default_keychain_is_usable",
        classmethod(lambda cls: usable_macos_keychain),
    )
    return module


def test_load_keyring_module_returns_none_when_dependency_missing(monkeypatch):
    """A genuinely missing keyring package must surface as None, not raise."""
    import importlib

    real_import_module = importlib.import_module

    def _block_keyring(name, *args, **kwargs):
        if name == "keyring" or name.startswith("keyring."):
            raise ModuleNotFoundError("No module named 'keyring'", name="keyring")
        return real_import_module(name, *args, **kwargs)

    monkeypatch.setattr(importlib, "import_module", _block_keyring)
    monkeypatch.delitem(sys.modules, "keyring", raising=False)
    SystemKeyringSecretStore._native_macos_security_reads_cache = None

    assert SystemKeyringSecretStore._load_keyring_module() is None


def test_system_keyring_reads_return_none_when_keyring_missing(monkeypatch):
    """Missing keyring must degrade reads instead of leaking ModuleNotFoundError."""
    monkeypatch.setattr(SystemKeyringSecretStore, "_load_keyring_module", staticmethod(lambda: None))
    SystemKeyringSecretStore._native_macos_security_reads_cache = None

    store = SystemKeyringSecretStore(service_name="hol-guard.test")

    assert store.get_secret("anything") is None
    assert store.get_secret_with_timeout("anything", timeout_seconds=1.0) is None


def test_system_keyring_set_secret_raises_clear_error_when_keyring_missing(monkeypatch):
    """Writes must raise an actionable RuntimeError, not a raw ModuleNotFoundError."""
    monkeypatch.setattr(SystemKeyringSecretStore, "_load_keyring_module", staticmethod(lambda: None))

    store = SystemKeyringSecretStore(service_name="hol-guard.test")

    with pytest.raises(RuntimeError) as exc_info:
        store.set_secret("anything", "value")

    message = str(exc_info.value).lower()
    assert "keyring" in message
    assert "unavailable" in message or "could not be imported" in message


def test_system_keyring_delete_secret_noops_when_keyring_missing(monkeypatch):
    monkeypatch.setattr(SystemKeyringSecretStore, "_load_keyring_module", staticmethod(lambda: None))

    store = SystemKeyringSecretStore(service_name="hol-guard.test")

    store.delete_secret("anything")  # must not raise


def test_system_keyring_is_available_false_when_keyring_missing(monkeypatch):
    monkeypatch.setattr(SystemKeyringSecretStore, "_load_keyring_module", staticmethod(lambda: None))
    SystemKeyringSecretStore._native_macos_security_reads_cache = None

    assert SystemKeyringSecretStore._backend_is_available() is False
    assert SystemKeyringSecretStore._is_available() is False


def test_load_keyring_module_propagates_broken_installed_keyring(monkeypatch):
    """A broken-but-installed keyring must surface, not silently degrade to None."""
    import importlib

    real_import_module = importlib.import_module

    def _break_keyring_subimport(name, *args, **kwargs):
        if name == "keyring":
            # keyring is installed but one of its own imports is missing.
            raise ModuleNotFoundError("No module named 'keyring._broken'", name="keyring._broken")
        return real_import_module(name, *args, **kwargs)

    monkeypatch.setattr(importlib, "import_module", _break_keyring_subimport)
    monkeypatch.delitem(sys.modules, "keyring", raising=False)

    with pytest.raises(ModuleNotFoundError):
        SystemKeyringSecretStore._load_keyring_module()


def test_load_keyring_module_or_none_logs_and_degrades_for_broken_keyring(monkeypatch, caplog):
    """A broken installed keyring is logged and degrades to None; never escapes."""

    def _raise_broken():
        raise RuntimeError("backend init failed")

    monkeypatch.setattr(SystemKeyringSecretStore, "_load_keyring_module", staticmethod(_raise_broken))
    SystemKeyringSecretStore._native_macos_security_reads_cache = None

    with caplog.at_level(logging.WARNING, logger="codex_plugin_scanner.guard.store"):
        assert SystemKeyringSecretStore._load_keyring_module_or_none() is None
        assert SystemKeyringSecretStore._backend_is_available() is False
        assert SystemKeyringSecretStore(service_name="hol-guard.test").get_secret("x") is None

    assert any("keyring backend could not be initialized" in record.message for record in caplog.records)


def test_system_keyring_timeout_skips_all_passive_macos_reads(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(guard_store_module.sys, "platform", "darwin", raising=False)
    secret_store = SystemKeyringSecretStore(service_name="hol-guard.policy-integrity")
    monkeypatch.setattr(
        SystemKeyringSecretStore,
        "_supports_native_macos_security_reads",
        classmethod(
            lambda cls: (_ for _ in ()).throw(AssertionError("native macOS Security reads should not be probed"))
        ),
    )
    monkeypatch.setattr(
        secret_store,
        "_get_secret_without_macos_ui",
        lambda _secret_id: (_ for _ in ()).throw(AssertionError("native macOS Security reads should not run")),
    )
    monkeypatch.setattr(
        secret_store,
        "get_secret",
        lambda _secret_id: (_ for _ in ()).throw(AssertionError("Python keyring reads should not run")),
    )
    monkeypatch.setattr(
        guard_store_module.subprocess,
        "run",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("security cli should not run")),
    )

    assert secret_store.get_secret_with_timeout("policy-key", timeout_seconds=1.0) is None


def test_system_keyring_timeout_keeps_non_policy_integrity_macos_services(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(guard_store_module.sys, "platform", "darwin", raising=False)
    secret_store = SystemKeyringSecretStore(service_name="hol-guard.oauth")
    monkeypatch.setattr(
        SystemKeyringSecretStore,
        "_supports_native_macos_security_reads",
        classmethod(lambda cls: True),
    )
    monkeypatch.setattr(secret_store, "_get_secret_without_macos_ui", lambda _secret_id: "oauth-secret")

    assert secret_store.get_secret_with_timeout("oauth-token", timeout_seconds=1.0) == "oauth-secret"


def test_system_keyring_timeout_blocks_non_policy_macos_prompt_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(guard_store_module.sys, "platform", "darwin", raising=False)
    secret_store = SystemKeyringSecretStore(service_name="hol-guard.oauth")
    monkeypatch.setattr(
        SystemKeyringSecretStore,
        "_supports_native_macos_security_reads",
        classmethod(lambda cls: False),
    )
    monkeypatch.setattr(
        secret_store,
        "get_secret",
        lambda _secret_id: (_ for _ in ()).throw(AssertionError("Python keyring reads should not run")),
    )

    assert secret_store.get_secret_with_timeout("oauth-token", timeout_seconds=1.0) is None


def test_policy_integrity_store_is_disabled_on_macos_without_health_probe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(guard_store_module.sys, "platform", "darwin", raising=False)
    module = _FakeSystemKeyringModule()
    monkeypatch.setattr(SystemKeyringSecretStore, "_load_keyring_module", staticmethod(lambda: module))
    monkeypatch.setattr(
        SystemKeyringSecretStore,
        "_macos_default_keychain_is_usable",
        classmethod(
            lambda cls: (_ for _ in ()).throw(AssertionError("policy integrity builder should skip health probe"))
        ),
    )

    secret_store = guard_store_module._build_policy_integrity_secret_store()

    assert secret_store is None


@pytest.fixture(autouse=True)
def _default_store_platform(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(guard_store_module.sys, "platform", "linux", raising=False)


@pytest.fixture(autouse=True)
def _clear_oauth_process_caches() -> None:
    guard_store_module._OAUTH_SECRET_PAYLOAD_PROCESS_CACHE.clear()
    guard_store_module._OAUTH_HEALTH_RESULT_PROCESS_CACHE.clear()
    yield
    guard_store_module._OAUTH_SECRET_PAYLOAD_PROCESS_CACHE.clear()
    guard_store_module._OAUTH_HEALTH_RESULT_PROCESS_CACHE.clear()


def _incomplete_evidence_table(connection: sqlite3.Connection) -> None:
    connection.execute(
        """
        create table guard_evidence (
          evidence_id text primary key,
          action_id text,
          request_id text,
          harness text,
          workspace text,
          signal_id text,
          category text,
          severity text,
          confidence real,
          summary text,
          details_json text,
          created_at text
        )
        """
    )


def test_guard_store_repairs_missing_evidence_table_when_schema_v4_is_applied(tmp_path):
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    database_path = guard_home / "guard.db"
    with sqlite3.connect(database_path) as connection:
        connection.execute("create table schema_migrations (version integer primary key, applied_at text not null)")
        connection.execute("insert into schema_migrations (version, applied_at) values (4, '2026-01-01T00:00:00Z')")
        connection.execute(
            """
            create table harness_installations (
              harness text primary key,
              active integer not null,
              workspace text,
              config_path text,
              metadata_json text not null default '{}',
              updated_at text not null
            )
            """
        )

    store = GuardStore(guard_home)
    store.add_evidence(
        EvidenceRecord(
            evidence_id="evidence-1",
            action_id="action-1",
            request_id="request-1",
            harness="codex",
            workspace="/workspace",
            signal_id="block",
            category="supply-chain",
            severity="high",
            confidence=1.0,
            summary="blocked package install",
            action_identity="rule-123",
        )
    )

    with sqlite3.connect(database_path) as connection:
        row = connection.execute(
            "select action_identity from guard_evidence where evidence_id = 'evidence-1'"
        ).fetchone()

    assert row is not None
    assert row[0] == "rule-123"


def test_guard_store_repairs_incomplete_evidence_table_missing_action_identity(tmp_path):
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    database_path = guard_home / "guard.db"
    with sqlite3.connect(database_path) as connection:
        connection.execute("create table schema_migrations (version integer primary key, applied_at text not null)")
        connection.execute("insert into schema_migrations (version, applied_at) values (4, '2026-01-01T00:00:00Z')")
        _incomplete_evidence_table(connection)

    store = GuardStore(guard_home)
    store.add_evidence(
        EvidenceRecord(
            evidence_id="evidence-legacy",
            action_id="action-legacy",
            request_id="request-legacy",
            harness="codex",
            workspace="/workspace",
            signal_id="ask",
            category="supply-chain",
            severity="medium",
            confidence=0.8,
            summary="package install requires review",
            action_identity="exception-456",
        )
    )

    with sqlite3.connect(database_path) as connection:
        columns = {str(row[1]) for row in connection.execute("pragma table_info(guard_evidence)").fetchall()}
        row = connection.execute(
            "select action_identity from guard_evidence where evidence_id = 'evidence-legacy'"
        ).fetchone()

    assert "action_identity" in columns
    assert row is not None
    assert row[0] == "exception-456"


def test_add_evidence_self_repairs_dropped_evidence_table(tmp_path):
    store = GuardStore(tmp_path / "guard-home")
    with sqlite3.connect(store.path) as connection:
        connection.execute("drop table guard_evidence")

    store.add_evidence(
        EvidenceRecord(
            evidence_id="evidence-repair",
            action_id="action-repair",
            request_id="request-repair",
            harness="codex",
            workspace="/workspace",
            signal_id="monitor",
            category="supply-chain",
            severity="low",
            confidence=0.5,
            summary="monitored package install",
        )
    )

    with sqlite3.connect(store.path) as connection:
        row = connection.execute(
            "select evidence_id from guard_evidence where evidence_id = 'evidence-repair'"
        ).fetchone()

    assert row is not None


def test_oauth_secret_store_skips_system_keyring_when_macos_default_keychain_is_missing(tmp_path, monkeypatch):
    _install_fake_system_keyring(monkeypatch, usable_macos_keychain=False)
    monkeypatch.setattr(guard_store_module.sys, "platform", "darwin", raising=False)
    SystemKeyringSecretStore._clear_macos_keychain_health_cache()
    monkeypatch.setattr(
        SystemKeyringSecretStore,
        "_macos_default_keychain_path",
        staticmethod(lambda: None),
    )

    secret_store = _build_oauth_secret_store(tmp_path / "guard-home")

    assert SystemKeyringSecretStore._is_available() is False
    assert isinstance(secret_store, UnavailableSecretStore)


def test_oauth_secret_store_skips_system_keyring_when_macos_user_keychain_search_list_is_broken(
    tmp_path,
    monkeypatch,
):
    _install_fake_system_keyring(monkeypatch, usable_macos_keychain=False)
    monkeypatch.setattr(guard_store_module.sys, "platform", "darwin", raising=False)
    SystemKeyringSecretStore._clear_macos_keychain_health_cache()
    usable_keychain = tmp_path / "Library" / "Keychains" / "login.keychain-db"
    usable_keychain.parent.mkdir(parents=True, exist_ok=True)
    usable_keychain.write_text("", encoding="utf-8")
    missing_keychain = tmp_path / "Library" / "Keychains" / "legacy.keychain-db"

    def fake_run(
        command: list[str],
        *,
        check: bool,
        capture_output: bool,
        text: bool,
        timeout: int,
    ) -> subprocess.CompletedProcess[str]:
        assert check is False
        assert capture_output is True
        assert text is True
        assert timeout == 5
        args = tuple(command[1:])
        if args == ("default-keychain", "-d", "user"):
            return subprocess.CompletedProcess(command, 0, stdout=f'"{usable_keychain}"\n', stderr="")
        if args == ("list-keychains", "-d", "user"):
            return subprocess.CompletedProcess(
                command,
                0,
                stdout=f'    "{usable_keychain}"\n    "{missing_keychain}"\n',
                stderr="",
            )
        if args == ("show-keychain-info", str(usable_keychain)):
            return subprocess.CompletedProcess(command, 0, stdout="", stderr="")
        raise AssertionError(f"Unexpected security command: {command!r}")

    monkeypatch.setattr(subprocess, "run", fake_run)

    secret_store = _build_oauth_secret_store(tmp_path / "guard-home")

    assert SystemKeyringSecretStore._is_available() is False
    assert isinstance(secret_store, UnavailableSecretStore)


def test_oauth_secret_store_uses_system_keyring_with_encrypted_fallback_on_macos_when_available(
    tmp_path,
    monkeypatch,
):
    _install_fake_system_keyring(monkeypatch, usable_macos_keychain=True)
    monkeypatch.setattr(guard_store_module.sys, "platform", "darwin", raising=False)
    SystemKeyringSecretStore._clear_macos_keychain_health_cache()

    secret_store = _build_oauth_secret_store(tmp_path / "guard-home")

    assert isinstance(secret_store, FallbackSecretStore)
    assert isinstance(secret_store.primary, SystemKeyringSecretStore)
    assert isinstance(secret_store.fallback, EncryptedFileSecretStore)


def test_oauth_secret_store_uses_cached_macos_availability_when_healthy(tmp_path, monkeypatch):
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir(parents=True)
    monkeypatch.setattr(guard_store_module.sys, "platform", "darwin", raising=False)
    guard_store_module._write_system_keyring_availability_cache(guard_home, available=True)
    monkeypatch.setattr(
        SystemKeyringSecretStore,
        "_is_available",
        classmethod(lambda cls: (_ for _ in ()).throw(AssertionError("cache miss"))),
    )

    secret_store = _build_oauth_secret_store(guard_home)

    assert isinstance(secret_store, FallbackSecretStore)
    assert isinstance(secret_store.primary, SystemKeyringSecretStore)
    assert isinstance(secret_store.fallback, EncryptedFileSecretStore)


def test_oauth_secret_store_unavailable_on_macos_does_not_create_local_secret_files(tmp_path, monkeypatch):
    _install_fake_system_keyring(monkeypatch, usable_macos_keychain=False)
    monkeypatch.setattr(guard_store_module.sys, "platform", "darwin", raising=False)
    SystemKeyringSecretStore._clear_macos_keychain_health_cache()
    guard_home = tmp_path / "guard-home"
    store = GuardStore(guard_home)

    with pytest.raises(RuntimeError, match="OS credential store"):
        store.set_oauth_local_credentials(
            issuer="https://hol.org",
            client_id="guard-local-daemon",
            refresh_token="refresh-secret-value",
            dpop_private_key_pem="-----BEGIN PRIVATE KEY-----\nsecret-key-material\n-----END PRIVATE KEY-----\n",
            dpop_public_jwk={
                "kty": "EC",
                "crv": "P-256",
                "x": "x-value",
                "y": "y-value",
                "alg": "ES256",
                "use": "sig",
            },
            dpop_public_jwk_thumbprint="thumbprint-123",
            now="2026-06-01T00:00:00+00:00",
        )

    assert not (guard_home / "secrets").exists()
    assert store.get_oauth_local_credential_health() == {
        "configured": False,
        "state": "not_configured",
        "backend": "unavailable",
        "fallback_backend": None,
    }


def test_oauth_secret_store_ignores_stale_macos_unavailable_cache_for_login(tmp_path, monkeypatch):
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir(parents=True)
    monkeypatch.setattr(guard_store_module.sys, "platform", "darwin", raising=False)
    guard_store_module._write_system_keyring_availability_cache(guard_home, available=False)
    monkeypatch.setattr(SystemKeyringSecretStore, "_is_available", classmethod(lambda cls: True))

    secret_store = _build_oauth_secret_store(guard_home)

    assert isinstance(secret_store, FallbackSecretStore)
    assert isinstance(secret_store.primary, SystemKeyringSecretStore)
    assert isinstance(secret_store.fallback, EncryptedFileSecretStore)


def test_oauth_secret_store_rechecks_stale_macos_health_cache_for_login(tmp_path, monkeypatch):
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir(parents=True)
    monkeypatch.setattr(guard_store_module.sys, "platform", "darwin", raising=False)
    fake_keyring = _FakeSystemKeyringModule()
    monkeypatch.setattr(SystemKeyringSecretStore, "_load_keyring_module", staticmethod(lambda: fake_keyring))
    SystemKeyringSecretStore._macos_keychain_health_cache = (guard_store_module.time.monotonic(), False)
    monkeypatch.setattr(
        SystemKeyringSecretStore, "_macos_default_keychain_is_usable_uncached", classmethod(lambda cls: True)
    )

    secret_store = _build_oauth_secret_store(guard_home)

    assert isinstance(secret_store, FallbackSecretStore)
    assert isinstance(secret_store.primary, SystemKeyringSecretStore)
    assert isinstance(secret_store.fallback, EncryptedFileSecretStore)


def test_macos_oauth_write_rejects_unreadable_keychain_secret(
    tmp_path,
    monkeypatch,
):
    guard_home = tmp_path / "guard-home"
    _install_fake_system_keyring(monkeypatch, usable_macos_keychain=True)
    monkeypatch.setattr(guard_store_module.sys, "platform", "darwin", raising=False)
    monkeypatch.setattr(SystemKeyringSecretStore, "get_secret_with_timeout", lambda *args, **kwargs: None)
    store = GuardStore(guard_home)

    with pytest.raises(RuntimeError, match="persist local Guard Cloud authorization securely"):
        store.set_oauth_local_credentials(
            issuer="https://hol.org",
            client_id="guard-local-daemon",
            refresh_token="refresh-secret-value",
            dpop_private_key_pem="-----BEGIN PRIVATE KEY-----\nsecret-key-material\n-----END PRIVATE KEY-----\n",
            dpop_public_jwk={
                "kty": "EC",
                "crv": "P-256",
                "x": "x-value",
                "y": "y-value",
                "alg": "ES256",
                "use": "sig",
            },
            dpop_public_jwk_thumbprint="thumbprint-123",
            now="2026-06-01T00:00:00+00:00",
        )

    assert store.get_sync_payload(guard_store_module._OAUTH_LOCAL_CREDENTIALS_STATE_KEY) is None
    assert store.get_oauth_local_credentials() is None


def test_oauth_health_uses_no_ui_primary_read_for_macos_keychain_only_store(tmp_path, monkeypatch):
    guard_home = tmp_path / "guard-home"
    fake_keyring = _install_fake_system_keyring(monkeypatch, usable_macos_keychain=True)
    monkeypatch.setattr(guard_store_module.sys, "platform", "darwin", raising=False)

    def fake_no_ui_read(self: SystemKeyringSecretStore, secret_id: str, *, timeout_seconds: float = 0.0) -> str | None:
        _ = timeout_seconds
        return fake_keyring.get_password(self.service_name, secret_id)

    monkeypatch.setattr(SystemKeyringSecretStore, "get_secret_with_timeout", fake_no_ui_read)
    store = GuardStore(guard_home)
    store.set_oauth_local_credentials(
        issuer="https://hol.org",
        client_id="guard-local-daemon",
        refresh_token="refresh-secret-value",
        dpop_private_key_pem="-----BEGIN PRIVATE KEY-----\nsecret-key-material\n-----END PRIVATE KEY-----\n",
        dpop_public_jwk={"kty": "EC", "crv": "P-256", "x": "x-value", "y": "y-value", "alg": "ES256", "use": "sig"},
        dpop_public_jwk_thumbprint="thumbprint-123",
        grant_id="grant-123",
        machine_id="machine-123",
        workspace_id="workspace-123",
        now="2026-06-01T00:00:00+00:00",
    )

    restarted_store = GuardStore(guard_home)

    assert restarted_store.get_oauth_local_credential_health()["state"] == "healthy"
    credentials = restarted_store.get_oauth_local_credentials()
    assert credentials is not None
    assert credentials["refresh_token"] == "refresh-secret-value"


def test_oauth_default_macos_keychain_read_uses_no_ui_path(tmp_path, monkeypatch):
    guard_home = tmp_path / "guard-home"
    fake_keyring = _install_fake_system_keyring(monkeypatch, usable_macos_keychain=True)
    monkeypatch.setattr(guard_store_module.sys, "platform", "darwin", raising=False)

    def fake_no_ui_read(self: SystemKeyringSecretStore, secret_id: str, *, timeout_seconds: float = 0.0) -> str | None:
        _ = timeout_seconds
        return fake_keyring._secrets.get((self.service_name, secret_id))

    monkeypatch.setattr(SystemKeyringSecretStore, "get_secret_with_timeout", fake_no_ui_read)
    store = GuardStore(guard_home)
    store.set_oauth_local_credentials(
        issuer="https://hol.org",
        client_id="guard-local-daemon",
        refresh_token="refresh-secret-value",
        dpop_private_key_pem="-----BEGIN PRIVATE KEY-----\nsecret-key-material\n-----END PRIVATE KEY-----\n",
        dpop_public_jwk={"kty": "EC", "crv": "P-256", "x": "x-value", "y": "y-value", "alg": "ES256", "use": "sig"},
        dpop_public_jwk_thumbprint="thumbprint-123",
        grant_id="grant-123",
        machine_id="machine-123",
        workspace_id="workspace-123",
        now="2026-06-01T00:00:00+00:00",
    )

    def fail_prompt_capable_read(service_name: str, secret_id: str) -> str | None:
        _ = (service_name, secret_id)
        raise AssertionError("default OAuth reads must use no-UI Keychain access")

    monkeypatch.setattr(fake_keyring, "get_password", fail_prompt_capable_read)
    restarted_store = GuardStore(guard_home)

    credentials = restarted_store.get_oauth_local_credentials()

    assert credentials is not None
    assert credentials["refresh_token"] == "refresh-secret-value"


def test_macos_oauth_default_reads_backfill_encrypted_fallback_from_keychain_only_state(
    tmp_path,
    monkeypatch,
):
    guard_home = tmp_path / "guard-home"
    fake_keyring = _install_fake_system_keyring(monkeypatch, usable_macos_keychain=True)
    monkeypatch.setattr(guard_store_module.sys, "platform", "darwin", raising=False)

    def fake_no_ui_read(self: SystemKeyringSecretStore, secret_id: str, *, timeout_seconds: float = 0.0) -> str | None:
        _ = timeout_seconds
        return fake_keyring._secrets.get((self.service_name, secret_id))

    monkeypatch.setattr(SystemKeyringSecretStore, "get_secret_with_timeout", fake_no_ui_read)
    store = GuardStore(guard_home)
    store.set_oauth_local_credentials(
        issuer="https://hol.org",
        client_id="guard-local-daemon",
        refresh_token="refresh-secret-value",
        dpop_private_key_pem="-----BEGIN PRIVATE KEY-----\nsecret-key-material\n-----END PRIVATE KEY-----\n",
        dpop_public_jwk={"kty": "EC", "crv": "P-256", "x": "x-value", "y": "y-value", "alg": "ES256", "use": "sig"},
        dpop_public_jwk_thumbprint="thumbprint-123",
        grant_id="grant-123",
        machine_id="machine-123",
        workspace_id="workspace-123",
        now="2026-06-01T00:00:00+00:00",
    )
    assert isinstance(store._oauth_secret_store, FallbackSecretStore)
    store._oauth_secret_store.fallback.delete_secret(store._oauth_local_credentials_ref)
    store._clear_oauth_secret_payload_cache()

    restarted_store = GuardStore(guard_home)

    credentials = restarted_store.get_oauth_local_credentials()

    assert credentials is not None
    assert credentials["refresh_token"] == "refresh-secret-value"
    assert isinstance(restarted_store._oauth_secret_store, FallbackSecretStore)
    assert restarted_store._oauth_secret_store.fallback.get_secret(restarted_store._oauth_local_credentials_ref)


def test_clear_oauth_local_credentials_removes_legacy_macos_encrypted_secret(tmp_path, monkeypatch):
    guard_home = tmp_path / "guard-home"
    monkeypatch.setattr(guard_store_module.sys, "platform", "darwin", raising=False)
    monkeypatch.setattr(SystemKeyringSecretStore, "_is_available", classmethod(lambda cls: False))
    store = GuardStore(guard_home)
    secret_ref = store._oauth_local_credentials_ref
    secret_hash = "f" * 64
    fallback = EncryptedFileSecretStore(guard_home)
    fallback.set_secret(secret_ref, json.dumps({"refresh_token": "legacy-refresh"}, sort_keys=True))
    legacy_path = fallback._path_for(secret_ref)
    store.set_sync_payload(
        guard_store_module._OAUTH_LOCAL_CREDENTIALS_STATE_KEY,
        {
            "issuer": "https://hol.org",
            "client_id": "guard-local-daemon",
            guard_store_module._OAUTH_LOCAL_CREDENTIALS_REF_KEY: secret_ref,
            guard_store_module._OAUTH_LOCAL_CREDENTIALS_HASH_KEY: secret_hash,
        },
        "2026-06-01T00:00:00+00:00",
    )

    store.clear_oauth_local_credentials()

    assert not legacy_path.exists()


def test_unavailable_oauth_secret_store_deletes_legacy_encrypted_secret(tmp_path):
    guard_home = tmp_path / "guard-home"
    fallback = EncryptedFileSecretStore(guard_home)
    secret_ref = "guard-oauth-local-credentials:test"
    fallback.set_secret(secret_ref, "legacy-secret")
    legacy_path = fallback._path_for(secret_ref)

    UnavailableSecretStore(guard_home).delete_secret(secret_ref)

    assert not legacy_path.exists()


def test_guard_store_ignores_persisted_system_keyring_unavailable_result_for_macos_oauth(
    tmp_path,
    monkeypatch,
):
    guard_home = tmp_path / "guard-home"
    monkeypatch.setattr(guard_store_module.sys, "platform", "darwin", raising=False)
    SystemKeyringSecretStore._clear_macos_keychain_health_cache()
    availability_checks = 0

    def fake_is_available(cls) -> bool:
        nonlocal availability_checks
        availability_checks += 1
        return False

    monkeypatch.setattr(SystemKeyringSecretStore, "_is_available", classmethod(fake_is_available))

    first_store = GuardStore(guard_home)

    assert isinstance(first_store._oauth_secret_store, UnavailableSecretStore)
    assert first_store._policy_integrity_secret_store is None

    SystemKeyringSecretStore._clear_macos_keychain_health_cache()

    second_store = GuardStore(guard_home)

    assert isinstance(second_store._oauth_secret_store, UnavailableSecretStore)
    assert second_store._policy_integrity_secret_store is None
    assert availability_checks == 2


def test_windows_oauth_refresh_lock_wraps_permission_error_as_blocking(monkeypatch):
    class _FakeHandle:
        def seek(self, _offset: int) -> None:
            return None

        def read(self, _size: int) -> bytes:
            raise PermissionError("locked")

        def write(self, _payload: bytes) -> int:
            return 0

        def flush(self) -> None:
            return None

        def fileno(self) -> int:
            return 1

    fake_msvcrt = types.SimpleNamespace(
        LK_NBLCK=1,
        locking=lambda _fd, _mode, _size: None,
    )
    monkeypatch.setattr(guard_store_module.os, "name", "nt", raising=False)
    monkeypatch.setitem(sys.modules, "msvcrt", fake_msvcrt)

    with pytest.raises(BlockingIOError):
        guard_store_module._acquire_advisory_file_lock(_FakeHandle())


def test_set_oauth_local_credentials_rejects_unallowlisted_issuer(tmp_path):
    store = GuardStore(tmp_path / "guard-home")

    with pytest.raises(ValueError, match="allowlisted HOL origin"):
        store.set_oauth_local_credentials(
            issuer="https://evil.example",
            client_id="guard-local-daemon",
            refresh_token="refresh-token",
            dpop_private_key_pem="private-key",
            dpop_public_jwk={"kty": "EC"},
            dpop_public_jwk_thumbprint="thumbprint",
            now="2026-04-19T00:00:00+00:00",
        )


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


def test_fallback_secret_store_logs_delete_failures(caplog):
    class FailingStore:
        def delete_secret(self, secret_id: str) -> None:
            raise RuntimeError(f"cannot delete {secret_id}")

    class MemoryStore:
        def __init__(self) -> None:
            self.deleted: list[str] = []

        def delete_secret(self, secret_id: str) -> None:
            self.deleted.append(secret_id)

    fallback = MemoryStore()
    store = FallbackSecretStore(FailingStore(), fallback)

    caplog.set_level(logging.WARNING, logger="codex_plugin_scanner.guard.store")
    store.delete_secret("guard-token")

    assert fallback.deleted == ["guard-token"]
    assert "Failed to delete Guard secret from FailingStore" in caplog.text
    assert "guard-token" not in caplog.text


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


def test_guard_store_secures_guard_home_and_database_permissions(tmp_path):
    if os.name == "nt":
        pytest.skip("POSIX-only permission assertions")

    store = GuardStore(tmp_path / "guard-home")

    assert store.guard_home.stat().st_mode & 0o777 == 0o700
    assert store.path.stat().st_mode & 0o777 == 0o600


def test_guard_store_repairs_existing_guard_home_and_database_permissions(tmp_path):
    if os.name == "nt":
        pytest.skip("POSIX-only permission assertions")

    guard_home = tmp_path / "guard-home"
    guard_home.mkdir(parents=True, exist_ok=True)
    os.chmod(guard_home, 0o755)
    database_path = guard_home / "guard.db"
    sqlite3.connect(database_path).close()
    os.chmod(database_path, 0o644)
    for name in ("guard.db-wal", "guard.db-shm", "guard.db-journal"):
        sidecar = guard_home / name
        sidecar.write_text("", encoding="utf-8")
        os.chmod(sidecar, 0o666)

    store = GuardStore(guard_home)

    assert store.guard_home.stat().st_mode & 0o777 == 0o700
    assert store.path.stat().st_mode & 0o777 == 0o600
    for name in ("guard.db-wal", "guard.db-shm", "guard.db-journal"):
        sidecar = guard_home / name
        if sidecar.exists():
            assert sidecar.stat().st_mode & 0o777 == 0o600


def test_oauth_local_credentials_are_not_persisted_in_plaintext_sqlite(tmp_path):
    store = GuardStore(tmp_path / "guard-home")
    store.set_oauth_local_credentials(
        issuer="https://hol.org",
        client_id="guard-local-daemon",
        refresh_token="refresh-secret-value",
        dpop_private_key_pem="-----BEGIN PRIVATE KEY-----\nsecret-key-material\n-----END PRIVATE KEY-----\n",
        dpop_public_jwk={
            "kty": "EC",
            "crv": "P-256",
            "x": "x-value",
            "y": "y-value",
            "alg": "ES256",
            "use": "sig",
        },
        dpop_public_jwk_thumbprint="thumbprint-123",
        grant_id="grant-123",
        machine_id="machine-123",
        workspace_id="workspace-123",
        now="2026-06-01T00:00:00+00:00",
    )

    with sqlite3.connect(store.path) as connection:
        row = connection.execute(
            "select payload_json from sync_state where state_key = 'oauth_local_credentials'"
        ).fetchone()

    assert row is not None
    payload = json.loads(str(row[0]))
    assert payload["issuer"] == "https://hol.org"
    assert payload["client_id"] == "guard-local-daemon"
    assert payload["grant_id"] == "grant-123"
    assert payload["machine_id"] == "machine-123"
    assert payload["workspace_id"] == "workspace-123"
    assert payload["credentials_ref"].startswith("guard-oauth-local-credentials:")
    assert isinstance(payload.get("credentials_sha256"), str)
    assert "refresh_token" not in payload
    assert "dpop_private_key_pem" not in payload
    assert "dpop_public_jwk" not in payload
    assert "dpop_public_jwk_thumbprint" not in payload

    assert store.get_oauth_local_credentials() == {
        "issuer": "https://hol.org",
        "client_id": "guard-local-daemon",
        "refresh_token": "refresh-secret-value",
        "dpop_private_key_pem": "-----BEGIN PRIVATE KEY-----\nsecret-key-material\n-----END PRIVATE KEY-----\n",
        "dpop_public_jwk": {
            "kty": "EC",
            "crv": "P-256",
            "x": "x-value",
            "y": "y-value",
            "alg": "ES256",
            "use": "sig",
        },
        "dpop_public_jwk_thumbprint": "thumbprint-123",
        "grant_id": "grant-123",
        "machine_id": "machine-123",
        "workspace_id": "workspace-123",
    }
    assert store.get_cloud_workspace_id() == "workspace-123"


def test_oauth_local_credentials_use_encrypted_file_fallback_when_system_keyring_write_fails(tmp_path, monkeypatch):
    guard_home = tmp_path / "guard-home"
    fake_keyring = _install_fake_system_keyring(monkeypatch)
    fake_keyring.fail_on_set = True
    store = GuardStore(guard_home)
    store.set_oauth_local_credentials(
        issuer="https://hol.org",
        client_id="guard-local-daemon",
        refresh_token="refresh-secret-value",
        dpop_private_key_pem="-----BEGIN PRIVATE KEY-----\nsecret-key-material\n-----END PRIVATE KEY-----\n",
        dpop_public_jwk={"kty": "EC", "crv": "P-256", "x": "x-value", "y": "y-value", "alg": "ES256", "use": "sig"},
        dpop_public_jwk_thumbprint="thumbprint-123",
        now="2026-06-01T00:00:00+00:00",
    )

    secrets_dir = guard_home / "secrets"
    assert secrets_dir.exists()
    assert any(path.name.endswith(".enc") for path in secrets_dir.iterdir())
    assert store.get_oauth_local_credentials() is not None


def test_oauth_local_credential_health_reports_backend_and_metadata(tmp_path, monkeypatch):
    monkeypatch.setattr(SystemKeyringSecretStore, "_is_available", classmethod(lambda cls: False))
    guard_home = tmp_path / "guard-home"
    store = GuardStore(guard_home)

    assert store.get_oauth_local_credential_health() == {
        "configured": False,
        "state": "not_configured",
        "backend": "encrypted-file",
        "fallback_backend": None,
    }

    store.set_oauth_local_credentials(
        issuer="https://hol.org",
        client_id="guard-local-daemon",
        refresh_token="refresh-secret-value",
        dpop_private_key_pem="-----BEGIN PRIVATE KEY-----\nsecret-key-material\n-----END PRIVATE KEY-----\n",
        dpop_public_jwk={"kty": "EC", "crv": "P-256", "x": "x-value", "y": "y-value", "alg": "ES256", "use": "sig"},
        dpop_public_jwk_thumbprint="thumbprint-123",
        grant_id="grant-123",
        machine_id="machine-123",
        workspace_id="workspace-123",
        now="2026-06-01T00:00:00+00:00",
    )

    assert store.get_oauth_local_credential_health() == {
        "configured": True,
        "state": "healthy",
        "backend": "encrypted-file",
        "fallback_backend": None,
        "issuer": "https://hol.org",
        "client_id": "guard-local-daemon",
        "grant_id": "grant-123",
        "machine_id": "machine-123",
        "workspace_id": "workspace-123",
    }
    assert store.get_oauth_local_credential_health()["state"] == "healthy"


def test_oauth_local_credential_health_reports_system_keyring_backend(tmp_path, monkeypatch):
    _install_fake_system_keyring(monkeypatch)
    store = GuardStore(tmp_path / "guard-home")

    store.set_oauth_local_credentials(
        issuer="https://hol.org",
        client_id="guard-local-daemon",
        refresh_token="refresh-secret-value",
        dpop_private_key_pem="-----BEGIN PRIVATE KEY-----\nsecret-key-material\n-----END PRIVATE KEY-----\n",
        dpop_public_jwk={"kty": "EC", "crv": "P-256", "x": "x-value", "y": "y-value", "alg": "ES256", "use": "sig"},
        dpop_public_jwk_thumbprint="thumbprint-123",
        grant_id="grant-123",
        machine_id="machine-123",
        workspace_id="workspace-123",
        now="2026-06-01T00:00:00+00:00",
    )

    assert store.get_oauth_local_credential_health() == {
        "configured": True,
        "state": "healthy",
        "backend": "system-keyring",
        "fallback_backend": "encrypted-file",
        "issuer": "https://hol.org",
        "client_id": "guard-local-daemon",
        "grant_id": "grant-123",
        "machine_id": "machine-123",
        "workspace_id": "workspace-123",
    }


def test_oauth_local_credentials_mirror_secret_into_encrypted_fallback_store(tmp_path, monkeypatch):
    _install_fake_system_keyring(monkeypatch)
    guard_home = tmp_path / "guard-home"
    store = GuardStore(guard_home)

    store.set_oauth_local_credentials(
        issuer="https://hol.org",
        client_id="guard-local-daemon",
        refresh_token="refresh-secret-value",
        dpop_private_key_pem="-----BEGIN PRIVATE KEY-----\nsecret-key-material\n-----END PRIVATE KEY-----\n",
        dpop_public_jwk={"kty": "EC", "crv": "P-256", "x": "x-value", "y": "y-value", "alg": "ES256", "use": "sig"},
        dpop_public_jwk_thumbprint="thumbprint-123",
        grant_id="grant-123",
        machine_id="machine-123",
        workspace_id="workspace-123",
        now="2026-06-01T00:00:00+00:00",
    )

    monkeypatch.setattr(SystemKeyringSecretStore, "_load_keyring_module", staticmethod(lambda: None))
    headless_store = GuardStore(guard_home)

    credentials = headless_store.get_oauth_local_credentials()

    assert credentials is not None
    assert credentials["refresh_token"] == "refresh-secret-value"
    assert headless_store.get_oauth_local_credential_health()["state"] == "healthy"


def test_set_oauth_local_credentials_skips_keyring_rewrite_when_secret_material_is_unchanged(tmp_path, monkeypatch):
    fake_keyring = _install_fake_system_keyring(monkeypatch)
    guard_home = tmp_path / "guard-home"
    store = GuardStore(guard_home)

    refresh_token = "refresh-token-1"
    rotated_refresh_token = "refresh-token-2"
    key_material = "key-material-1"

    store.set_oauth_local_credentials(
        issuer="https://hol.org",
        client_id="guard-local-daemon",
        refresh_token=refresh_token,
        dpop_private_key_pem=key_material,
        dpop_public_jwk={"kty": "EC", "crv": "P-256", "x": "x-value", "y": "y-value", "alg": "ES256", "use": "sig"},
        dpop_public_jwk_thumbprint="thumbprint-123",
        grant_id="grant-123",
        machine_id="machine-123",
        workspace_id="workspace-123",
        supply_chain_plan_id="starter",
        now="2026-06-01T00:00:00+00:00",
    )

    assert fake_keyring.set_password_calls_by_service.get("hol-guard.oauth", 0) == 1

    store.set_oauth_local_credentials(
        issuer="https://hol.org",
        client_id="guard-local-daemon",
        refresh_token=refresh_token,
        dpop_private_key_pem=key_material,
        dpop_public_jwk={"kty": "EC", "crv": "P-256", "x": "x-value", "y": "y-value", "alg": "ES256", "use": "sig"},
        dpop_public_jwk_thumbprint="thumbprint-123",
        grant_id="grant-123",
        machine_id="machine-123",
        workspace_id="workspace-123",
        supply_chain_firewall=True,
        supply_chain_plan_id="team",
        now="2026-06-01T00:05:00+00:00",
    )

    assert fake_keyring.set_password_calls_by_service.get("hol-guard.oauth", 0) == 1
    credentials = store.get_oauth_local_credentials()

    assert credentials is not None
    assert credentials["refresh_token"] == refresh_token
    assert credentials["dpop_private_key_pem"] == key_material
    assert credentials["supply_chain_firewall"] is True
    assert credentials["supply_chain_plan_id"] == "team"

    store.set_oauth_local_credentials(
        issuer="https://hol.org",
        client_id="guard-local-daemon",
        refresh_token=rotated_refresh_token,
        dpop_private_key_pem=key_material,
        dpop_public_jwk={"kty": "EC", "crv": "P-256", "x": "x-value", "y": "y-value", "alg": "ES256", "use": "sig"},
        dpop_public_jwk_thumbprint="thumbprint-123",
        grant_id="grant-123",
        machine_id="machine-123",
        workspace_id="workspace-123",
        supply_chain_firewall=True,
        supply_chain_plan_id="team",
        now="2026-06-01T00:10:00+00:00",
    )

    assert fake_keyring.set_password_calls_by_service.get("hol-guard.oauth", 0) == 2
    rotated_credentials = store.get_oauth_local_credentials()

    assert rotated_credentials is not None
    assert rotated_credentials["refresh_token"] == rotated_refresh_token


def test_get_oauth_local_credentials_prefers_validated_encrypted_fallback_before_keyring(tmp_path, monkeypatch):
    fake_keyring = _install_fake_system_keyring(monkeypatch)
    monkeypatch.setattr(guard_store_module.sys, "platform", "linux", raising=False)
    guard_home = tmp_path / "guard-home"
    store = GuardStore(guard_home)
    assert isinstance(store._oauth_secret_store, FallbackSecretStore)
    assert isinstance(store._oauth_secret_store.fallback, EncryptedFileSecretStore)

    store.set_oauth_local_credentials(
        issuer="https://hol.org",
        client_id="guard-local-daemon",
        refresh_token="refresh-secret-value",
        dpop_private_key_pem="-----BEGIN PRIVATE KEY-----\nsecret-key-material\n-----END PRIVATE KEY-----\n",
        dpop_public_jwk={"kty": "EC", "crv": "P-256", "x": "x-value", "y": "y-value", "alg": "ES256", "use": "sig"},
        dpop_public_jwk_thumbprint="thumbprint-123",
        grant_id="grant-123",
        machine_id="machine-123",
        workspace_id="workspace-123",
        now="2026-06-01T00:00:00+00:00",
    )

    fallback_reads = 0
    original_fallback_get_secret = store._oauth_secret_store.fallback.get_secret

    def count_fallback_reads(secret_id: str) -> str | None:
        nonlocal fallback_reads
        fallback_reads += 1
        return original_fallback_get_secret(secret_id)

    monkeypatch.setattr(store._oauth_secret_store.fallback, "get_secret", count_fallback_reads)
    store._clear_oauth_secret_payload_cache()

    credentials = store.get_oauth_local_credentials()
    repeated_credentials = store.get_oauth_local_credentials()

    assert credentials is not None
    assert repeated_credentials is not None
    assert credentials["refresh_token"] == "refresh-secret-value"
    assert store.get_cloud_sync_profile() == {
        "auth_mode": "oauth",
        "sync_url": "https://hol.org/api/guard/receipts/sync",
        "workspace_id": "workspace-123",
    }
    assert fallback_reads == 1
    assert fake_keyring.get_password_calls_by_service.get("hol-guard.oauth", 0) == 0


def test_get_oauth_local_credentials_fails_closed_when_fallback_hash_is_stale(tmp_path, monkeypatch):
    _install_fake_system_keyring(monkeypatch)
    guard_home = tmp_path / "guard-home"
    store = GuardStore(guard_home)
    assert isinstance(store._oauth_secret_store, FallbackSecretStore)

    store.set_oauth_local_credentials(
        issuer="https://hol.org",
        client_id="guard-local-daemon",
        refresh_token="refresh-secret-value",
        dpop_private_key_pem="-----BEGIN PRIVATE KEY-----\nsecret-key-material\n-----END PRIVATE KEY-----\n",
        dpop_public_jwk={"kty": "EC", "crv": "P-256", "x": "x-value", "y": "y-value", "alg": "ES256", "use": "sig"},
        dpop_public_jwk_thumbprint="thumbprint-123",
        grant_id="grant-123",
        machine_id="machine-123",
        workspace_id="workspace-123",
        now="2026-06-01T00:00:00+00:00",
    )
    oauth_payload = store.get_sync_payload("oauth_local_credentials")
    assert isinstance(oauth_payload, dict)
    oauth_payload["credentials_sha256"] = "pbkdf2-sha256$" + ("0" * 64)
    store.set_sync_payload("oauth_local_credentials", oauth_payload, "2026-06-01T00:01:00+00:00")

    def fail_primary_lookup(_secret_id: str, *, timeout_seconds: float) -> str | None:
        assert timeout_seconds > 0
        return None

    monkeypatch.setattr(store._oauth_secret_store.primary, "get_secret_with_timeout", fail_primary_lookup)

    assert store.get_oauth_local_credentials() is None
    assert store.get_oauth_local_credential_health()["state"] == "degraded"


def test_get_oauth_local_credentials_recovers_from_timed_primary_lookup_when_fallback_hash_is_stale(
    tmp_path,
    monkeypatch,
):
    fake_keyring = _install_fake_system_keyring(monkeypatch)
    guard_home = tmp_path / "guard-home"
    store = GuardStore(guard_home)
    assert isinstance(store._oauth_secret_store, FallbackSecretStore)

    store.set_oauth_local_credentials(
        issuer="https://hol.org",
        client_id="guard-local-daemon",
        refresh_token="refresh-secret-value",
        dpop_private_key_pem="-----BEGIN PRIVATE KEY-----\nsecret-key-material\n-----END PRIVATE KEY-----\n",
        dpop_public_jwk={"kty": "EC", "crv": "P-256", "x": "x-value", "y": "y-value", "alg": "ES256", "use": "sig"},
        dpop_public_jwk_thumbprint="thumbprint-123",
        grant_id="grant-123",
        machine_id="machine-123",
        workspace_id="workspace-123",
        now="2026-06-01T00:00:00+00:00",
    )
    oauth_payload = store.get_sync_payload("oauth_local_credentials")
    assert isinstance(oauth_payload, dict)
    secret_id = str(oauth_payload["credentials_ref"])
    original_secret = fake_keyring.get_password("hol-guard.oauth", secret_id)
    assert isinstance(original_secret, str)
    updated_secret_payload = json.loads(original_secret)
    assert isinstance(updated_secret_payload, dict)
    updated_secret_payload["refresh_token"] = "refresh-secret-value-rotated"
    updated_secret = json.dumps(updated_secret_payload)
    fake_keyring.set_password("hol-guard.oauth", secret_id, updated_secret)
    oauth_payload["credentials_sha256"] = guard_store_module._secret_fingerprint(updated_secret)
    store.set_sync_payload("oauth_local_credentials", oauth_payload, "2026-06-01T00:01:00+00:00")

    assert isinstance(store._oauth_secret_store.primary, SystemKeyringSecretStore)
    primary_secret = fake_keyring.get_password("hol-guard.oauth", secret_id)
    assert isinstance(primary_secret, str)
    monkeypatch.setattr(
        store._oauth_secret_store.primary,
        "get_secret",
        lambda _secret_id: (_ for _ in ()).throw(AssertionError("plain primary lookup should not run")),
    )
    monkeypatch.setattr(
        store._oauth_secret_store.primary,
        "get_secret_with_timeout",
        lambda _secret_id, *, timeout_seconds: primary_secret,
    )

    primary_reads = 0

    def count_primary_reads(_secret_id: str, *, timeout_seconds: float) -> str | None:
        nonlocal primary_reads
        primary_reads += 1
        return primary_secret

    monkeypatch.setattr(store._oauth_secret_store.primary, "get_secret_with_timeout", count_primary_reads)

    credentials = store.get_oauth_local_credentials(allow_primary=True)
    repeated_credentials = store.get_oauth_local_credentials(allow_primary=True)

    assert credentials is not None
    assert repeated_credentials is not None
    assert credentials["refresh_token"] == "refresh-secret-value-rotated"
    assert primary_reads == 1
    assert store.get_oauth_local_credential_health()["state"] == "healthy"


def test_get_recoverable_oauth_local_credentials_uses_encrypted_fallback_when_hash_is_stale(tmp_path, monkeypatch):
    _install_fake_system_keyring(monkeypatch)
    guard_home = tmp_path / "guard-home"
    store = GuardStore(guard_home)
    assert isinstance(store._oauth_secret_store, FallbackSecretStore)

    store.set_oauth_local_credentials(
        issuer="https://hol.org",
        client_id="guard-local-daemon",
        refresh_token="refresh-secret-value",
        dpop_private_key_pem="-----BEGIN PRIVATE KEY-----\nsecret-key-material\n-----END PRIVATE KEY-----\n",
        dpop_public_jwk={"kty": "EC", "crv": "P-256", "x": "x-value", "y": "y-value", "alg": "ES256", "use": "sig"},
        dpop_public_jwk_thumbprint="thumbprint-123",
        grant_id="grant-123",
        machine_id="machine-123",
        workspace_id="workspace-123",
        now="2026-06-01T00:00:00+00:00",
    )
    oauth_payload = store.get_sync_payload("oauth_local_credentials")
    assert isinstance(oauth_payload, dict)
    oauth_payload["credentials_sha256"] = "pbkdf2-sha256$" + ("0" * 64)
    store.set_sync_payload("oauth_local_credentials", oauth_payload, "2026-06-01T00:01:00+00:00")

    assert store.get_oauth_local_credentials() is None

    recoverable = store.get_recoverable_oauth_local_credentials()

    assert recoverable is not None
    assert recoverable["refresh_token"] == "refresh-secret-value"
    assert recoverable["workspace_id"] == "workspace-123"


def test_set_oauth_local_credentials_rejects_incomplete_fallback_mirror(tmp_path, monkeypatch, caplog):
    _install_fake_system_keyring(monkeypatch)
    guard_home = tmp_path / "guard-home"
    store = GuardStore(guard_home)
    assert isinstance(store._oauth_secret_store, FallbackSecretStore)

    def fail_fallback_set_secret(secret_id: str, value: str) -> None:
        raise RuntimeError("disk full")

    monkeypatch.setattr(store._oauth_secret_store.fallback, "set_secret", fail_fallback_set_secret)
    caplog.set_level(logging.WARNING, logger="codex_plugin_scanner.guard.store")

    try:
        store.set_oauth_local_credentials(
            issuer="https://hol.org",
            client_id="guard-local-daemon",
            refresh_token="refresh-secret-value",
            dpop_private_key_pem="-----BEGIN PRIVATE KEY-----\nsecret-key-material\n-----END PRIVATE KEY-----\n",
            dpop_public_jwk={"kty": "EC", "crv": "P-256", "x": "x-value", "y": "y-value", "alg": "ES256", "use": "sig"},
            dpop_public_jwk_thumbprint="thumbprint-123",
            grant_id="grant-123",
            machine_id="machine-123",
            workspace_id="workspace-123",
            now="2026-06-01T00:00:00+00:00",
        )
    except RuntimeError as error:
        assert str(error) == "Guard could not persist local Guard Cloud authorization into the encrypted local store."
    else:
        raise AssertionError("OAuth persistence should fail when the encrypted fallback mirror is missing")

    assert store.get_sync_payload("oauth_local_credentials") is None
    assert store.get_oauth_local_credentials() is None
    assert "Failed to mirror OAuth credentials into encrypted fallback store" in caplog.text


def test_get_oauth_local_credentials_backfills_encrypted_fallback_for_legacy_keyring_only_state(tmp_path, monkeypatch):
    _install_fake_system_keyring(monkeypatch)
    monkeypatch.setattr(guard_store_module.sys, "platform", "linux", raising=False)
    guard_home = tmp_path / "guard-home"
    store = GuardStore(guard_home)

    store.set_oauth_local_credentials(
        issuer="https://hol.org",
        client_id="guard-local-daemon",
        refresh_token="refresh-secret-value",
        dpop_private_key_pem="-----BEGIN PRIVATE KEY-----\nsecret-key-material\n-----END PRIVATE KEY-----\n",
        dpop_public_jwk={"kty": "EC", "crv": "P-256", "x": "x-value", "y": "y-value", "alg": "ES256", "use": "sig"},
        dpop_public_jwk_thumbprint="thumbprint-123",
        grant_id="grant-123",
        machine_id="machine-123",
        workspace_id="workspace-123",
        now="2026-06-01T00:00:00+00:00",
    )
    assert isinstance(store._oauth_secret_store, FallbackSecretStore)
    store._oauth_secret_store.fallback.delete_secret(store._oauth_local_credentials_ref)
    store._clear_oauth_secret_payload_cache()

    credentials = store.get_oauth_local_credentials(allow_primary=True)

    assert credentials is not None
    assert store._oauth_secret_store.fallback.get_secret(store._oauth_local_credentials_ref) is not None

    monkeypatch.setattr(SystemKeyringSecretStore, "_load_keyring_module", staticmethod(lambda: None))
    headless_store = GuardStore(guard_home)

    assert headless_store.get_oauth_local_credentials(allow_primary=False) is not None


def test_get_oauth_local_credential_health_avoids_primary_keychain_reads(tmp_path, monkeypatch):
    _install_fake_system_keyring(monkeypatch)
    monkeypatch.setattr(guard_store_module.sys, "platform", "linux", raising=False)
    guard_home = tmp_path / "guard-home"
    store = GuardStore(guard_home)
    store.set_oauth_local_credentials(
        issuer="https://hol.org",
        client_id="guard-local-daemon",
        refresh_token="refresh-secret-value",
        dpop_private_key_pem="-----BEGIN PRIVATE KEY-----\nsecret-key-material\n-----END PRIVATE KEY-----\n",
        dpop_public_jwk={"kty": "EC", "crv": "P-256", "x": "x-value", "y": "y-value", "alg": "ES256", "use": "sig"},
        dpop_public_jwk_thumbprint="thumbprint-123",
        grant_id="grant-123",
        machine_id="machine-123",
        workspace_id="workspace-123",
        now="2026-06-01T00:00:00+00:00",
    )
    assert isinstance(store._oauth_secret_store, FallbackSecretStore)
    store._oauth_secret_store.fallback.delete_secret(store._oauth_local_credentials_ref)
    store._clear_oauth_secret_payload_cache()

    primary_reads = 0

    def count_primary_reads(_secret_id: str, *, timeout_seconds: float) -> str | None:
        nonlocal primary_reads
        primary_reads += 1
        return store._oauth_secret_store.primary.get_secret(_secret_id)

    monkeypatch.setattr(store._oauth_secret_store.primary, "get_secret_with_timeout", count_primary_reads)

    for _ in range(10):
        health = store.get_oauth_local_credential_health()
        assert health["state"] == "healthy"

    assert primary_reads == 1


def test_oauth_secret_payload_process_cache_is_shared_across_store_instances(tmp_path, monkeypatch):
    _install_fake_system_keyring(monkeypatch)
    monkeypatch.setattr(guard_store_module.sys, "platform", "linux", raising=False)
    guard_home = tmp_path / "guard-home"
    store = GuardStore(guard_home)
    store.set_oauth_local_credentials(
        issuer="https://hol.org",
        client_id="guard-local-daemon",
        refresh_token="refresh-secret-value",
        dpop_private_key_pem="-----BEGIN PRIVATE KEY-----\nsecret-key-material\n-----END PRIVATE KEY-----\n",
        dpop_public_jwk={"kty": "EC", "crv": "P-256", "x": "x-value", "y": "y-value", "alg": "ES256", "use": "sig"},
        dpop_public_jwk_thumbprint="thumbprint-123",
        grant_id="grant-123",
        machine_id="machine-123",
        workspace_id="workspace-123",
        now="2026-06-01T00:00:00+00:00",
    )
    assert isinstance(store._oauth_secret_store, FallbackSecretStore)
    store._oauth_secret_store.fallback.delete_secret(store._oauth_local_credentials_ref)
    store._clear_oauth_secret_payload_cache()

    primary_reads = 0

    def count_primary_reads(_secret_id: str, *, timeout_seconds: float) -> str | None:
        nonlocal primary_reads
        primary_reads += 1
        return store._oauth_secret_store.primary.get_secret(_secret_id)

    monkeypatch.setattr(store._oauth_secret_store.primary, "get_secret_with_timeout", count_primary_reads)

    assert store.get_oauth_local_credentials(allow_primary=True) is not None
    assert primary_reads == 1

    second_store = GuardStore(guard_home)
    assert second_store.get_oauth_local_credentials(allow_primary=True) is not None
    assert primary_reads == 1


def test_repair_oauth_local_credential_storage_from_primary_repairs_stale_encrypted_fallback(tmp_path, monkeypatch):
    fake_keyring = _install_fake_system_keyring(monkeypatch)
    guard_home = tmp_path / "guard-home"
    store = GuardStore(guard_home)
    store.set_oauth_local_credentials(
        issuer="https://hol.org",
        client_id="guard-local-daemon",
        refresh_token="refresh-secret-value",
        dpop_private_key_pem="-----BEGIN PRIVATE KEY-----\nsecret-key-material\n-----END PRIVATE KEY-----\n",
        dpop_public_jwk={"kty": "EC", "crv": "P-256", "x": "x-value", "y": "y-value", "alg": "ES256", "use": "sig"},
        dpop_public_jwk_thumbprint="thumbprint-123",
        grant_id="grant-123",
        machine_id="machine-123",
        workspace_id="workspace-123",
        now="2026-06-01T00:00:00+00:00",
    )
    oauth_payload = store.get_sync_payload("oauth_local_credentials")
    assert isinstance(oauth_payload, dict)
    secret_id = str(oauth_payload["credentials_ref"])
    rotated_secret_payload = json.loads(fake_keyring.get_password("hol-guard.oauth", secret_id) or "{}")
    rotated_secret_payload["refresh_token"] = "refresh-secret-value-rotated"
    rotated_secret = json.dumps(rotated_secret_payload)
    fake_keyring.set_password("hol-guard.oauth", secret_id, rotated_secret)
    oauth_payload["credentials_sha256"] = guard_store_module._secret_fingerprint(rotated_secret)
    store.set_sync_payload("oauth_local_credentials", oauth_payload, "2026-06-01T00:01:00+00:00")

    primary_reads = 0
    original = store._oauth_secret_store.primary.get_secret_with_timeout

    def count_primary_reads(_secret_id: str, *, timeout_seconds: float) -> str | None:
        nonlocal primary_reads
        primary_reads += 1
        return original(_secret_id, timeout_seconds=timeout_seconds)

    monkeypatch.setattr(store._oauth_secret_store.primary, "get_secret_with_timeout", count_primary_reads)

    assert store.get_oauth_local_credentials(allow_primary=False) is None
    assert store.repair_oauth_local_credential_storage_from_primary() is True
    health = store.get_oauth_local_credential_health()
    repeated_health = store.get_oauth_local_credential_health()

    assert health["state"] == "healthy"
    assert repeated_health["state"] == "healthy"
    assert primary_reads == 1
    assert store._oauth_secret_store.fallback.get_secret(secret_id) == rotated_secret

    second_store = GuardStore(guard_home)
    assert second_store.repair_oauth_local_credential_storage_from_primary() is False
    assert primary_reads == 1


def test_oauth_health_auto_repairs_stale_encrypted_fallback_from_primary(tmp_path, monkeypatch):
    fake_keyring = _install_fake_system_keyring(monkeypatch)
    guard_home = tmp_path / "guard-home"
    store = GuardStore(guard_home)
    store.set_oauth_local_credentials(
        issuer="https://hol.org",
        client_id="guard-local-daemon",
        refresh_token="refresh-secret-value",
        dpop_private_key_pem="-----BEGIN PRIVATE KEY-----[REDACTED:Private key block]\\n",
        dpop_public_jwk={"kty": "EC", "crv": "P-256", "x": "x-value", "y": "y-value", "alg": "ES256", "use": "sig"},
        dpop_public_jwk_thumbprint="thumbprint-123",
        grant_id="grant-123",
        machine_id="machine-123",
        workspace_id="workspace-123",
        now="2026-06-01T00:00:00+00:00",
    )
    oauth_payload = store.get_sync_payload("oauth_local_credentials")
    assert isinstance(oauth_payload, dict)
    secret_id = str(oauth_payload["credentials_ref"])
    rotated_secret_payload = json.loads(fake_keyring.get_password("hol-guard.oauth", secret_id) or "{}")
    rotated_secret_payload["refresh_token"] = "refresh-secret-value-rotated"
    rotated_secret = json.dumps(rotated_secret_payload, sort_keys=True, separators=(",", ":"))
    fake_keyring.set_password("hol-guard.oauth", secret_id, rotated_secret)
    oauth_payload["credentials_sha256"] = guard_store_module._secret_fingerprint(rotated_secret)
    store.set_sync_payload("oauth_local_credentials", oauth_payload, "2026-06-01T00:01:00+00:00")

    primary_reads = 0
    original = store._oauth_secret_store.primary.get_secret_with_timeout

    def count_primary_reads(_secret_id: str, *, timeout_seconds: float) -> str | None:
        nonlocal primary_reads
        primary_reads += 1
        return original(_secret_id, timeout_seconds=timeout_seconds)

    monkeypatch.setattr(store._oauth_secret_store.primary, "get_secret_with_timeout", count_primary_reads)

    health = store.get_oauth_local_credential_health()
    profile = store.get_cloud_sync_profile()
    repeated_health = store.get_oauth_local_credential_health()

    assert health["state"] == "healthy"
    assert repeated_health["state"] == "healthy"
    assert primary_reads == 1
    assert store._oauth_secret_store.fallback.get_secret(secret_id) == rotated_secret
    assert profile == {
        "auth_mode": "oauth",
        "sync_url": "https://hol.org/api/guard/receipts/sync",
        "workspace_id": "workspace-123",
    }


def test_oauth_health_does_not_repair_from_recoverable_fallback_when_hash_is_stale(
    tmp_path,
    monkeypatch,
):
    fake_keyring = _install_fake_system_keyring(monkeypatch)
    guard_home = tmp_path / "guard-home"
    store = GuardStore(guard_home)
    store.set_oauth_local_credentials(
        issuer="https://hol.org",
        client_id="guard-local-daemon",
        refresh_token="refresh-secret-value",
        dpop_private_key_pem="-----BEGIN PRIVATE KEY-----[REDACTED:Private key block]\\n",
        dpop_public_jwk={"kty": "EC", "crv": "P-256", "x": "x-value", "y": "y-value", "alg": "ES256", "use": "sig"},
        dpop_public_jwk_thumbprint="thumbprint-123",
        grant_id="grant-123",
        machine_id="machine-123",
        workspace_id="workspace-123",
        now="2026-06-01T00:00:00+00:00",
    )
    oauth_payload = store.get_sync_payload("oauth_local_credentials")
    assert isinstance(oauth_payload, dict)
    secret_id = str(oauth_payload["credentials_ref"])
    fallback_secret = store._oauth_secret_store.fallback.get_secret(secret_id)
    assert isinstance(fallback_secret, str)
    fake_keyring.delete_password("hol-guard.oauth", secret_id)
    oauth_payload["credentials_sha256"] = "pbkdf2-sha256$" + ("0" * 64)
    store.set_sync_payload("oauth_local_credentials", oauth_payload, "2026-06-01T00:01:00+00:00")

    health = store.get_oauth_local_credential_health()
    profile = store.get_cloud_sync_profile()
    repaired_payload = store.get_sync_payload("oauth_local_credentials")

    assert health["state"] == "degraded"
    assert store.get_oauth_local_credentials() is None
    assert profile is None
    assert isinstance(repaired_payload, dict)
    assert repaired_payload["credentials_sha256"] == "pbkdf2-sha256$" + ("0" * 64)


def test_oauth_health_does_not_repair_from_recoverable_fallback_when_macos_keychain_readback_is_unavailable(
    tmp_path,
    monkeypatch,
):
    fake_keyring = _install_fake_system_keyring(monkeypatch)
    monkeypatch.setattr(guard_store_module.sys, "platform", "darwin", raising=False)
    guard_home = tmp_path / "guard-home"
    store = GuardStore(guard_home)
    monkeypatch.setattr(
        store._oauth_secret_store.primary,
        "get_secret_with_timeout",
        lambda secret_id, *, timeout_seconds: store._oauth_secret_store.primary.get_secret(secret_id),
    )
    store.set_oauth_local_credentials(
        issuer="https://hol.org",
        client_id="guard-local-daemon",
        refresh_token="refresh-secret-value",
        dpop_private_key_pem="-----BEGIN PRIVATE KEY-----[REDACTED:Private key block]\\n",
        dpop_public_jwk={"kty": "EC", "crv": "P-256", "x": "x-value", "y": "y-value", "alg": "ES256", "use": "sig"},
        dpop_public_jwk_thumbprint="thumbprint-123",
        grant_id="grant-123",
        machine_id="machine-123",
        workspace_id="workspace-123",
        now="2026-06-01T00:00:00+00:00",
    )
    oauth_payload = store.get_sync_payload("oauth_local_credentials")
    assert isinstance(oauth_payload, dict)
    secret_id = str(oauth_payload["credentials_ref"])
    fallback_secret = store._oauth_secret_store.fallback.get_secret(secret_id)
    assert isinstance(fallback_secret, str)
    fake_keyring.delete_password("hol-guard.oauth", secret_id)
    oauth_payload["credentials_sha256"] = "pbkdf2-sha256$" + ("0" * 64)
    store.set_sync_payload("oauth_local_credentials", oauth_payload, "2026-06-01T00:01:00+00:00")
    monkeypatch.setattr(
        store._oauth_secret_store.primary,
        "get_secret_with_timeout",
        lambda _secret_id, *, timeout_seconds: None,
    )

    health = store.get_oauth_local_credential_health()
    profile = store.get_cloud_sync_profile()
    repaired_payload = store.get_sync_payload("oauth_local_credentials")

    assert health["state"] == "degraded"
    assert store.get_oauth_local_credentials(allow_primary=False) is None
    assert profile is None
    assert isinstance(repaired_payload, dict)
    assert repaired_payload["credentials_sha256"] == "pbkdf2-sha256$" + ("0" * 64)


def test_oauth_health_caches_degraded_state_between_failed_repair_attempts(tmp_path, monkeypatch):
    fake_keyring = _install_fake_system_keyring(monkeypatch)
    monkeypatch.setattr(guard_store_module.sys, "platform", "linux", raising=False)
    guard_home = tmp_path / "guard-home"
    store = GuardStore(guard_home)
    store.set_oauth_local_credentials(
        issuer="https://hol.org",
        client_id="guard-local-daemon",
        refresh_token="refresh-secret-value",
        dpop_private_key_pem="-----BEGIN PRIVATE KEY-----[REDACTED:Private key block]\\n",
        dpop_public_jwk={"kty": "EC", "crv": "P-256", "x": "x-value", "y": "y-value", "alg": "ES256", "use": "sig"},
        dpop_public_jwk_thumbprint="thumbprint-123",
        grant_id="grant-123",
        machine_id="machine-123",
        workspace_id="workspace-123",
        now="2026-06-01T00:00:00+00:00",
    )
    oauth_payload = store.get_sync_payload("oauth_local_credentials")
    assert isinstance(oauth_payload, dict)
    secret_id = str(oauth_payload["credentials_ref"])
    assert isinstance(store._oauth_secret_store, FallbackSecretStore)
    store._oauth_secret_store.fallback.delete_secret(secret_id)
    fake_keyring.delete_password("hol-guard.oauth", secret_id)
    store._clear_oauth_secret_payload_cache()

    repair_calls = 0
    original_repair = store.repair_oauth_local_credential_storage_from_primary

    def count_repair_calls() -> bool:
        nonlocal repair_calls
        repair_calls += 1
        return original_repair()

    monkeypatch.setattr(store, "repair_oauth_local_credential_storage_from_primary", count_repair_calls)

    first_health = store.get_oauth_local_credential_health()
    second_health = store.get_oauth_local_credential_health()

    assert first_health["state"] == "degraded"
    assert second_health["state"] == "degraded"
    assert repair_calls == 1


def test_get_cloud_sync_profile_uses_oauth_metadata_without_primary_keychain_reads(tmp_path, monkeypatch):
    _install_fake_system_keyring(monkeypatch)
    guard_home = tmp_path / "guard-home"
    store = GuardStore(guard_home)
    store.set_oauth_local_credentials(
        issuer="https://hol.org",
        client_id="guard-local-daemon",
        refresh_token="refresh-secret-value",
        dpop_private_key_pem="-----BEGIN PRIVATE KEY-----\nsecret-key-material\n-----END PRIVATE KEY-----\n",
        dpop_public_jwk={"kty": "EC", "crv": "P-256", "x": "x-value", "y": "y-value", "alg": "ES256", "use": "sig"},
        dpop_public_jwk_thumbprint="thumbprint-123",
        grant_id="grant-123",
        machine_id="machine-123",
        workspace_id="workspace-123",
        now="2026-06-01T00:00:00+00:00",
    )
    assert isinstance(store._oauth_secret_store, FallbackSecretStore)
    assert store.get_oauth_local_credential_health()["state"] == "healthy"

    primary_reads = 0

    def count_primary_reads(_secret_id: str, *, timeout_seconds: float) -> str | None:
        nonlocal primary_reads
        primary_reads += 1
        return store._oauth_secret_store.primary.get_secret(_secret_id)

    monkeypatch.setattr(store._oauth_secret_store.primary, "get_secret_with_timeout", count_primary_reads)

    profile = store.get_cloud_sync_profile()

    assert profile == {
        "auth_mode": "oauth",
        "sync_url": "https://hol.org/api/guard/receipts/sync",
        "workspace_id": "workspace-123",
    }
    assert primary_reads == 0
