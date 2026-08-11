"""Regression coverage for desktop policy-integrity local-vault recovery."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import local_trust_controller as local_trust_controller_module
from codex_plugin_scanner.guard import store_policy_integrity_backend as policy_integrity_backend_module
from codex_plugin_scanner.guard.local_trust_controller import resolve_passive_trust_state
from codex_plugin_scanner.guard.models import PolicyDecision
from codex_plugin_scanner.guard.store import (
    EncryptedFileSecretStore,
    GuardStore,
    MigratingFallbackSecretStore,
    SystemKeyringSecretStore,
)


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


def test_linux_system_keyring_mirrors_policy_integrity_into_local_vault(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Keep the OS keyring while adding a prompt-free mirror for daemon and headless reads.
    monkeypatch.setattr(policy_integrity_backend_module.sys, "platform", "linux", raising=False)
    monkeypatch.setattr(
        SystemKeyringSecretStore,
        "_backend_is_available",
        classmethod(lambda cls: True),
    )

    store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)

    secret_store = store._policy_integrity_secret_store
    assert isinstance(secret_store, MigratingFallbackSecretStore)
    assert isinstance(secret_store.primary, SystemKeyringSecretStore)
    assert isinstance(secret_store.fallback, EncryptedFileSecretStore)


def test_linux_local_vault_keeps_policy_valid_when_system_keyring_becomes_unavailable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(policy_integrity_backend_module.sys, "platform", "linux", raising=False)
    monkeypatch.setattr(
        SystemKeyringSecretStore,
        "_backend_is_available",
        classmethod(lambda cls: True),
    )
    primary_values: dict[str, str] = {}
    monkeypatch.setattr(
        SystemKeyringSecretStore, "set_secret", lambda self, key, value: primary_values.__setitem__(key, value)
    )
    monkeypatch.setattr(SystemKeyringSecretStore, "get_secret", lambda self, key: primary_values.get(key))
    monkeypatch.setattr(
        SystemKeyringSecretStore,
        "get_secret_with_timeout",
        lambda self, key, *, timeout_seconds: primary_values.get(key),
    )

    guard_home = tmp_path / "guard-home"
    store = GuardStore(guard_home, prime_policy_integrity=False)
    store.setup_policy_integrity(now="2026-08-11T20:00:00Z", include_items=False)
    store.upsert_policy(
        PolicyDecision(
            harness="guard-cli",
            scope="artifact",
            action="allow",
            artifact_id="guard-cli:project:package-request",
            artifact_hash="approval-context",
        ),
        "2026-08-11T20:01:00Z",
    )

    monkeypatch.setattr(
        SystemKeyringSecretStore,
        "get_secret",
        lambda self, key: (_ for _ in ()).throw(RuntimeError("keyring unavailable")),
    )
    restarted = GuardStore(guard_home, prime_policy_integrity=False)
    status = restarted.get_policy_integrity_status()

    assert status["mode"] == "protected"
    assert status["trust_status"]["remembered_rules"] == "enforced"
    assert (
        restarted.resolve_policy(
            "guard-cli",
            "guard-cli:project:package-request",
            "approval-context",
            now="2026-08-11T20:02:00Z",
        )
        == "allow"
    )


def test_linux_migrates_existing_system_keyring_policy_before_headless_restart(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(policy_integrity_backend_module.sys, "platform", "linux", raising=False)
    monkeypatch.setattr(
        SystemKeyringSecretStore,
        "_backend_is_available",
        classmethod(lambda cls: True),
    )
    primary_values: dict[str, str] = {}
    monkeypatch.setattr(
        SystemKeyringSecretStore,
        "set_secret",
        lambda self, key, value: primary_values.__setitem__(key, value),
    )
    monkeypatch.setattr(SystemKeyringSecretStore, "get_secret", lambda self, key: primary_values.get(key))
    monkeypatch.setattr(
        SystemKeyringSecretStore,
        "get_secret_with_timeout",
        lambda self, key, *, timeout_seconds: primary_values.get(key),
    )

    guard_home = tmp_path / "guard-home"
    legacy = GuardStore(guard_home, prime_policy_integrity=False)
    legacy._policy_integrity_secret_store = SystemKeyringSecretStore(service_name="hol-guard.policy-integrity")
    legacy.setup_policy_integrity(now="2026-08-11T20:00:00Z", include_items=False)
    legacy.upsert_policy(
        PolicyDecision(
            harness="guard-cli",
            scope="artifact",
            action="allow",
            artifact_id="guard-cli:project:legacy-package-request",
            artifact_hash="legacy-approval-context",
        ),
        "2026-08-11T20:01:00Z",
    )

    migrated = GuardStore(guard_home, prime_policy_integrity=False)
    assert migrated.get_policy_integrity_status()["mode"] == "protected"

    def _keyring_unavailable(*args: object, **kwargs: object) -> str | None:
        raise RuntimeError("keyring unavailable")

    monkeypatch.setattr(SystemKeyringSecretStore, "get_secret", _keyring_unavailable)
    monkeypatch.setattr(SystemKeyringSecretStore, "get_secret_with_timeout", _keyring_unavailable)
    restarted = GuardStore(guard_home, prime_policy_integrity=False)

    assert restarted.get_policy_integrity_status()["mode"] == "protected"
    assert (
        restarted.resolve_policy(
            "guard-cli",
            "guard-cli:project:legacy-package-request",
            "legacy-approval-context",
            now="2026-08-11T20:02:00Z",
        )
        == "allow"
    )


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
