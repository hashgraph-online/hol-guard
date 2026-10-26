"""Windows keeps the policy-integrity key in the local vault for every session."""

from __future__ import annotations

import base64
import logging
import os
import sys
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.store import GuardStore, SystemKeyringSecretStore
from codex_plugin_scanner.guard.store_policy_integrity_windows import WindowsPolicyIntegritySecretStore


def _no_logon_session() -> OSError:
    error = OSError(1312, "A specified logon session does not exist.")
    error.__dict__["winerror"] = 1312
    return error


class _CredentialManager:
    """Credential Manager as an interactive or a credential-less session sees it."""

    def __init__(self) -> None:
        self.secrets: dict[tuple[str, str], str] = {}
        self.session_available = True
        self.writes = 0

    def _require_session(self) -> None:
        if not self.session_available:
            raise _no_logon_session()

    def get_password(self, service: str, secret_id: str) -> str | None:
        self._require_session()
        return self.secrets.get((service, secret_id))

    def set_password(self, service: str, secret_id: str, value: str) -> None:
        self._require_session()
        self.writes += 1
        self.secrets[(service, secret_id)] = value

    def delete_password(self, service: str, secret_id: str) -> None:
        self._require_session()
        self.secrets.pop((service, secret_id), None)


@pytest.fixture
def credential_manager(monkeypatch: pytest.MonkeyPatch) -> _CredentialManager:
    manager = _CredentialManager()
    monkeypatch.setattr(sys, "platform", "win32", raising=False)
    monkeypatch.setattr(SystemKeyringSecretStore, "_backend_is_available", classmethod(lambda cls: True))
    monkeypatch.setattr(SystemKeyringSecretStore, "_load_keyring_module_or_none", classmethod(lambda cls: manager))
    return manager


def _store(guard_home: Path) -> tuple[GuardStore, WindowsPolicyIntegritySecretStore]:
    store = GuardStore(guard_home, prime_policy_integrity=False)
    secret_store = store._policy_integrity_secret_store
    assert isinstance(secret_store, WindowsPolicyIntegritySecretStore)
    return store, secret_store


def test_sessionless_logon_keeps_the_key_in_the_vault_for_later_sessions(
    tmp_path: Path,
    credential_manager: _CredentialManager,
    caplog: pytest.LogCaptureFixture,
) -> None:
    credential_manager.session_available = False
    with caplog.at_level(logging.WARNING, logger="codex_plugin_scanner.guard.store"):
        store, secret_store = _store(tmp_path / "guard-home")
        state = store.setup_policy_integrity(now="2026-10-07T21:00:00Z", include_items=False)

    assert state["backend"] == "encrypted-file"
    assert state["mode"] == "protected"
    assert state["degraded_reasons"] == []
    assert "degraded" not in caplog.text
    key_ref = store._policy_integrity_key_ref
    vault_key = secret_store.fallback.get_secret(key_ref)
    assert vault_key is not None

    credential_manager.session_available = True
    interactive, _ = _store(tmp_path / "guard-home")
    assert interactive.setup_policy_integrity(now="2026-10-07T21:01:00Z", include_items=False)["mode"] == "protected"
    assert interactive._policy_integrity_secret_store.get_secret(key_ref) == vault_key
    assert credential_manager.writes == 0
    assert credential_manager.secrets == {}


def test_interactive_logon_moves_a_legacy_credential_manager_key_into_the_vault(
    tmp_path: Path,
    credential_manager: _CredentialManager,
) -> None:
    store, secret_store = _store(tmp_path / "guard-home")
    key_ref = store._policy_integrity_key_ref
    legacy_key = base64.urlsafe_b64encode(os.urandom(32)).decode("ascii")
    credential_manager.secrets[(secret_store.primary.service_name, key_ref)] = legacy_key

    state = store.setup_policy_integrity(now="2026-10-07T21:00:00Z", include_items=False)

    assert state["mode"] == "protected"
    assert state["backend"] == "encrypted-file"
    assert secret_store.fallback.get_secret(key_ref) == legacy_key
    assert credential_manager.secrets == {}


def test_sessionless_reset_refuses_to_leave_a_credential_manager_copy_behind(
    tmp_path: Path,
    credential_manager: _CredentialManager,
) -> None:
    store, secret_store = _store(tmp_path / "guard-home")
    key_ref = store._policy_integrity_key_ref
    secret_store.fallback.set_secret(key_ref, "vault-key")
    credential_manager.secrets[(secret_store.primary.service_name, key_ref)] = "older-key"

    credential_manager.session_available = False
    with pytest.raises(RuntimeError, match="Credential Manager"):
        secret_store.delete_secret(key_ref)
    assert secret_store.fallback.get_secret(key_ref) == "vault-key"

    credential_manager.session_available = True
    secret_store.delete_secret(key_ref)
    assert secret_store.get_secret(key_ref) is None
    assert credential_manager.secrets == {}


def test_credential_manager_errors_other_than_a_missing_session_still_raise(
    tmp_path: Path,
    credential_manager: _CredentialManager,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, secret_store = _store(tmp_path / "guard-home")

    def denied(_service: str, _secret_id: str) -> str | None:
        raise PermissionError("access denied")

    monkeypatch.setattr(credential_manager, "get_password", denied)

    with pytest.raises(PermissionError, match="access denied"):
        secret_store.get_secret("integrity-key")
