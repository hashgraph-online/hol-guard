"""Regression coverage for desktop policy-integrity local-vault recovery."""

from __future__ import annotations

import base64
import sqlite3
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import local_trust_controller as local_trust_controller_module
from codex_plugin_scanner.guard import store_policy_integrity_backend as policy_integrity_backend_module
from codex_plugin_scanner.guard.local_trust_controller import resolve_passive_trust_state
from codex_plugin_scanner.guard.models import PolicyDecision
from codex_plugin_scanner.guard.native_command_control_authority import AUTHORITY_FILE_NAME, encode_authority
from codex_plugin_scanner.guard.native_command_control_authority_io import write_private_state
from codex_plugin_scanner.guard.native_command_control_authority_store import (
    _key as native_authority_key,
)
from codex_plugin_scanner.guard.native_command_control_authority_store import (
    read_command_control_authority,
)
from codex_plugin_scanner.guard.store import (
    EncryptedFileSecretStore,
    GuardStore,
    SystemKeyringSecretStore,
)
from codex_plugin_scanner.guard.store_policy_integrity_backend import MirroredPolicyIntegritySecretStore


def _disable_system_keyring(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(policy_integrity_backend_module.sys, "platform", "linux", raising=False)
    monkeypatch.setattr(
        SystemKeyringSecretStore,
        "_backend_is_available",
        classmethod(lambda cls: False),
    )


def test_linux_policy_integrity_uses_local_vault_without_system_keyring(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _disable_system_keyring(monkeypatch)

    store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)

    assert isinstance(store._policy_integrity_secret_store, EncryptedFileSecretStore)
    before = store.get_policy_integrity_status()
    assert before["mode"] == "degraded"

    repaired = store.setup_policy_integrity(now="2026-08-07T20:00:00Z", include_items=False)

    assert repaired["mode"] == "protected"
    assert repaired["trust_status"]["runtime_protection"] == "protected"
    assert repaired["trust_status"]["remembered_rules"] == "enforced"

    artifact_id = "codex:project:tampered-local-vault"
    store.upsert_policy(
        PolicyDecision(
            harness="codex", scope="artifact", action="allow", artifact_id=artifact_id, artifact_hash="hash"
        ),
        "2026-08-07T20:01:00Z",
    )
    with sqlite3.connect(store.guard_home / "guard.db") as connection:
        connection.execute(
            "update policy_decisions set payload_mac = ? where artifact_id = ?", ("deadbeef", artifact_id)
        )
        before_row = connection.execute(
            "select * from policy_decisions where artifact_id = ?", (artifact_id,)
        ).fetchone()
    assert store.verify_policy_integrity()["counts"]["tampered"] == 1

    rerun = store.setup_policy_integrity(now="2026-08-07T20:02:00Z", include_items=False)
    with sqlite3.connect(store.guard_home / "guard.db") as connection:
        after_row = connection.execute(
            "select * from policy_decisions where artifact_id = ?", (artifact_id,)
        ).fetchone()

    assert rerun["mode"] == "protected"
    assert after_row == before_row
    assert store.verify_policy_integrity()["counts"]["tampered"] == 1


def test_linux_system_keyring_secret_is_mirrored_for_terminal_session(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    keyring_values: dict[str, str] = {}
    monkeypatch.setattr(policy_integrity_backend_module.sys, "platform", "linux", raising=False)
    monkeypatch.setattr(
        SystemKeyringSecretStore,
        "_backend_is_available",
        classmethod(lambda cls: True),
    )
    monkeypatch.setattr(
        SystemKeyringSecretStore,
        "get_secret",
        lambda self, secret_id: keyring_values.get(secret_id),
    )
    monkeypatch.setattr(
        SystemKeyringSecretStore,
        "set_secret",
        lambda self, secret_id, value: keyring_values.__setitem__(secret_id, value),
    )

    guard_home = tmp_path / "guard-home"
    daemon = GuardStore(guard_home, prime_policy_integrity=False)
    secret_store = daemon._policy_integrity_secret_store
    assert isinstance(secret_store, MirroredPolicyIntegritySecretStore)
    verifier_key = native_authority_key(daemon)
    authority = {
        "schema": "guard.native-command-control-authority.v1",
        "epoch": 1,
        "mutation_revision": 1,
        "authority_key_id": "0" * 64,
        "phase": "closed",
        "effective_digest": None,
        "recovery": None,
    }
    encoded = encode_authority(authority, verifier_key)
    write_private_state(guard_home, AUTHORITY_FILE_NAME, encoded, 4096)

    # A prior terminal session could have selected the local vault while the
    # daemon used the keyring. The reachable keyring must repair that split.
    secret_store.fallback.set_secret(
        daemon._policy_integrity_key_ref,
        base64.urlsafe_b64encode(b"\x01" * 32).decode("ascii"),
    )
    refreshed_daemon = GuardStore(guard_home, prime_policy_integrity=False)
    assert read_command_control_authority(refreshed_daemon, native_authority_key(refreshed_daemon)) is not None

    monkeypatch.setattr(
        SystemKeyringSecretStore,
        "_backend_is_available",
        classmethod(lambda cls: False),
    )
    terminal = GuardStore(guard_home, prime_policy_integrity=False)
    assert isinstance(terminal._policy_integrity_secret_store, EncryptedFileSecretStore)
    assert read_command_control_authority(terminal, native_authority_key(terminal)) is not None


def test_linux_unavailable_legacy_keyring_does_not_replace_armed_native_key(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _disable_system_keyring(monkeypatch)
    guard_home = tmp_path / "guard-home"
    native_state = guard_home / "native-runtime"
    native_state.mkdir(parents=True)
    (native_state / AUTHORITY_FILE_NAME).write_bytes(b"existing authority")

    store = GuardStore(guard_home, prime_policy_integrity=False)

    assert store._policy_integrity_secret_material(create=True) == (None, None)


def test_mirrored_policy_keyring_write_failure_keeps_existing_vault_value(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    primary = SystemKeyringSecretStore(service_name="hol-guard.test")
    fallback = EncryptedFileSecretStore(tmp_path)
    fallback.set_secret("integrity-key", "old")

    def fail_write(_secret_id: str, _value: str) -> None:
        raise RuntimeError("keyring unavailable")

    monkeypatch.setattr(primary, "set_secret", fail_write)
    mirrored = MirroredPolicyIntegritySecretStore(primary, fallback)

    with pytest.raises(RuntimeError, match="keyring unavailable"):
        mirrored.set_secret("integrity-key", "new")
    assert fallback.get_secret("integrity-key") == "old"


def test_mirrored_policy_keyring_remains_readable_when_vault_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    primary = SystemKeyringSecretStore(service_name="hol-guard.test")
    monkeypatch.setattr(primary, "get_secret_with_timeout", lambda _secret_id, *, timeout_seconds: "keyring-value")

    class FailingVault:
        def get_secret(self, _secret_id: str) -> str | None:
            raise RuntimeError("vault unavailable")

        def set_secret(self, _secret_id: str, _value: str) -> None:
            raise RuntimeError("vault unavailable")

        def delete_secret(self, _secret_id: str) -> None:
            raise RuntimeError("vault unavailable")

    mirrored = MirroredPolicyIntegritySecretStore(primary, FailingVault())

    assert mirrored.get_secret("integrity-key") == "keyring-value"


def test_mirrored_policy_reset_rejects_stale_keyring_secret(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    primary = SystemKeyringSecretStore(service_name="hol-guard.test")
    fallback = EncryptedFileSecretStore(tmp_path)
    fallback.set_secret("integrity-key", "old")
    monkeypatch.setattr(primary, "delete_secret", lambda _secret_id: None)
    monkeypatch.setattr(primary, "get_secret_with_timeout", lambda _secret_id, *, timeout_seconds: "old")
    mirrored = MirroredPolicyIntegritySecretStore(primary, fallback)

    with pytest.raises(RuntimeError, match="keyring deletion did not persist"):
        mirrored.delete_secret("integrity-key")
    assert fallback.get_secret("integrity-key") == "old"


def test_doctor_can_report_protected_after_linux_local_vault_repair(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _disable_system_keyring(monkeypatch)
    store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)
    repaired = store.setup_policy_integrity(now="2026-08-07T20:00:00Z", include_items=False)

    monkeypatch.setattr(
        local_trust_controller_module,
        "load_authenticated_daemon_state",
        lambda _guard_home: {"trust_status": repaired["trust_status"]},
    )

    resolved = resolve_passive_trust_state(store, backend_requested="auto")

    assert resolved.backend_selected == "local-vault"
    assert resolved.mode == "protected"
    assert resolved.trust_status.runtime_protection == "protected"
    assert resolved.trust_status.remembered_rules == "enforced"
