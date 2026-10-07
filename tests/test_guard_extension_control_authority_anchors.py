"""Credential migration and crash-safe anchor transitions."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime.command_extensions import (
    BUILT_IN_COMMAND_EXTENSION_REGISTRY,
)
from codex_plugin_scanner.guard.runtime.extension_control_authority import (
    AuthorityHealth,
    AuthorityPhase,
    ExtensionControlAuthorityError,
)
from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.store_base import (
    EncryptedFileSecretStore,
    MigratingFallbackSecretStore,
    SystemKeyringSecretStore,
)

from .guard_extension_control_authority_fixtures import (
    _PASSWORD as _PASSWORD,
)
from .guard_extension_control_authority_fixtures import (
    MemorySecretStore as MemorySecretStore,
)
from .guard_extension_control_authority_fixtures import (
    _allow_local_terminal_confirmation as _allow_local_terminal_confirmation,
)
from .guard_extension_control_authority_fixtures import (
    _commit as _commit,
)
from .guard_extension_control_authority_fixtures import (
    _commit_enabled_permission as _commit_enabled_permission,
)
from .guard_extension_control_authority_fixtures import (
    _disabled_layer as _disabled_layer,
)
from .guard_extension_control_authority_fixtures import (
    _enroll as _enroll,
)
from .guard_extension_control_authority_fixtures import (
    _enrollment_proof as _enrollment_proof,
)
from .guard_extension_control_authority_fixtures import (
    _expanded_permission_registry as _expanded_permission_registry,
)
from .guard_extension_control_authority_fixtures import (
    _matcher_contract_registry as _matcher_contract_registry,
)
from .guard_extension_control_authority_fixtures import (
    _proof as _proof,
)
from .guard_extension_control_authority_fixtures import (
    _rule_version_registry as _rule_version_registry,
)
from .guard_extension_control_authority_fixtures import (
    _store as _store,
)
from .guard_extension_control_authority_fixtures import (
    _upgraded_registry as _upgraded_registry,
)


def test_linux_legacy_keyring_authority_migrates_then_survives_keyring_loss(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(sys, "platform", "linux")
    legacy_secrets = MemorySecretStore()
    legacy_store = _store(tmp_path, legacy_secrets)
    assert (
        legacy_store.read_extension_control_authority(
            catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest
        ).health
        is AuthorityHealth.PROTECTED
    )
    monkeypatch.setattr(
        SystemKeyringSecretStore,
        "get_secret",
        lambda _self, secret_id: legacy_secrets.get_secret(secret_id),
    )
    monkeypatch.setattr(SystemKeyringSecretStore, "set_secret", lambda _self, _secret_id, _value: None)

    migrated = GuardStore(tmp_path, prime_policy_integrity=False)
    assert (
        migrated.read_extension_control_authority(
            catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest
        ).health
        is AuthorityHealth.PROTECTED
    )

    monkeypatch.setattr(
        SystemKeyringSecretStore,
        "get_secret",
        lambda _self, _secret_id: (_ for _ in ()).throw(RuntimeError("session keyring disappeared")),
    )
    restarted = GuardStore(tmp_path, prime_policy_integrity=False)
    assert (
        restarted.read_extension_control_authority(
            catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest
        ).health
        is AuthorityHealth.PROTECTED
    )


def test_macos_extension_authority_default_never_probes_keychain(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def forbid_keychain_probe(self: SystemKeyringSecretStore) -> bool:
        raise AssertionError("keychain probe")

    monkeypatch.setattr(sys, "platform", "darwin")
    monkeypatch.setattr(SystemKeyringSecretStore, "_is_available", forbid_keychain_probe)

    store = GuardStore(tmp_path, prime_policy_integrity=False)

    assert isinstance(store._secret_store(), EncryptedFileSecretStore)


def test_explicit_macos_extension_authority_migration_enables_passive_vault_reads(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(sys, "platform", "darwin")
    legacy_secrets = MemorySecretStore()
    legacy_store = _store(tmp_path, legacy_secrets)
    legacy_view = legacy_store.read_extension_control_authority(
        catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest
    )
    assert legacy_view.health is AuthorityHealth.PROTECTED
    monkeypatch.setattr(
        SystemKeyringSecretStore,
        "get_secret",
        lambda _self, secret_id: legacy_secrets.get_secret(secret_id),
    )
    explicit_store = GuardStore(tmp_path, prime_policy_integrity=False, allow_system_keyring=True)

    assert explicit_store.migrate_legacy_extension_control_authority_secrets() is True

    monkeypatch.setattr(
        SystemKeyringSecretStore,
        "get_secret",
        lambda _self, _secret_id: (_ for _ in ()).throw(AssertionError("passive read probed Keychain")),
    )
    passive_store = GuardStore(tmp_path, prime_policy_integrity=False)
    passive_view = passive_store.read_extension_control_authority(
        catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest
    )

    assert passive_view.health is AuthorityHealth.PROTECTED


def test_explicit_macos_extension_authority_migration_rejects_partial_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(sys, "platform", "darwin")
    legacy_secrets = MemorySecretStore()
    legacy_store = _store(tmp_path, legacy_secrets)
    legacy_store.read_extension_control_authority(catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest)
    anchor_ref = legacy_store._anchor_ref()
    legacy_secrets.delete_secret(anchor_ref)
    monkeypatch.setattr(
        SystemKeyringSecretStore,
        "get_secret",
        lambda _self, secret_id: legacy_secrets.get_secret(secret_id),
    )
    explicit_store = GuardStore(tmp_path, prime_policy_integrity=False, allow_system_keyring=True)

    assert explicit_store.migrate_legacy_extension_control_authority_secrets() is False


def test_explicit_macos_extension_authority_spends_one_interactive_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(sys, "platform", "darwin")
    legacy_secrets = MemorySecretStore()
    legacy_store = _store(tmp_path, legacy_secrets)
    legacy_store.read_extension_control_authority(catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest)
    interactive_reads: list[str] = []
    bounded_reads: list[str] = []

    def tracked_interactive_read(secret_id: str) -> str | None:
        interactive_reads.append(secret_id)
        return legacy_secrets.get_secret(secret_id)

    def tracked_bounded_read(
        secret_id: str,
        *,
        timeout_seconds: float = 0.0,
    ) -> str | None:
        _ = timeout_seconds
        bounded_reads.append(secret_id)
        return legacy_secrets.get_secret(secret_id)

    monkeypatch.setattr(
        SystemKeyringSecretStore, "get_secret", lambda _self, secret_id: legacy_secrets.get_secret(secret_id)
    )
    monkeypatch.setattr(
        SystemKeyringSecretStore,
        "get_secret_with_timeout",
        lambda _self, secret_id, **_kwargs: legacy_secrets.get_secret(secret_id),
    )
    explicit_store = GuardStore(tmp_path, prime_policy_integrity=False, allow_system_keyring=True)
    migrating = explicit_store._secret_store()
    assert isinstance(migrating, MigratingFallbackSecretStore)
    assert isinstance(migrating.primary, SystemKeyringSecretStore)
    # Other shard tests can leave background stores reading their own homes.
    # Track every read by this store without counting unrelated backend instances.
    monkeypatch.setattr(migrating.primary, "get_secret", tracked_interactive_read)
    monkeypatch.setattr(migrating.primary, "get_secret_with_timeout", tracked_bounded_read)
    unrelated = SystemKeyringSecretStore(service_name="unrelated-test-store")
    unrelated.get_secret("unrelated-key")
    unrelated.get_secret_with_timeout("unrelated-anchor", timeout_seconds=0.5)
    assert interactive_reads == []
    assert bounded_reads == []

    assert explicit_store.migrate_legacy_extension_control_authority_secrets() is True
    assert interactive_reads == [legacy_store._key_ref()]
    assert bounded_reads == [legacy_store._anchor_ref()]


def test_failed_anchor_write_leaves_recoverable_prepared_transition(tmp_path: Path) -> None:
    secrets = MemorySecretStore()
    store = _store(tmp_path, secrets)
    store.read_extension_control_authority(catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest)
    secrets.fail_anchor_set_number = secrets.anchor_set_count + 1
    with pytest.raises(ExtensionControlAuthorityError, match="anchor"):
        _commit(store)

    with store._connect() as connection:
        row = connection.execute(
            "select phase from extension_control_authority_transition order by revision desc limit 1"
        ).fetchone()
    assert row["phase"] == AuthorityPhase.PREPARED.value
    recovered = store.recover_extension_control_authority(
        catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest
    )
    assert recovered.health is AuthorityHealth.PROTECTED
    assert recovered.revision == 0


def test_idempotent_retry_after_prepared_transition_commits_once(tmp_path: Path) -> None:
    secrets = MemorySecretStore()
    store = _store(tmp_path, secrets)
    store.read_extension_control_authority(catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest)
    secrets.fail_anchor_set_number = secrets.anchor_set_count + 1
    with pytest.raises(ExtensionControlAuthorityError, match="anchor"):
        _commit(store)

    retried = store.commit_extension_control_layers(
        (_disabled_layer(),),
        catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
        actor_id="local-admin",
        expected_revision=0,
        idempotency_key="change-1",
        nonce="nonce-change-1",
        proof=_proof(
            store,
            (_disabled_layer(),),
            revision=0,
            key="change-1",
            actor_id="local-admin",
            nonce="nonce-change-1",
        ),
    )

    assert retried.health is AuthorityHealth.PROTECTED
    assert retried.revision == 1
    with store._connect() as connection:
        count = connection.execute("select count(*) from extension_control_authority_transition").fetchone()[0]
        event_count = connection.execute(
            "select count(*) from guard_cloud_events where event_type = 'policy.changed'"
        ).fetchone()[0]
    assert event_count == 1
    assert count == 1


def test_recovery_finalizes_database_commit_when_final_anchor_write_failed(tmp_path: Path) -> None:
    secrets = MemorySecretStore()
    store = _store(tmp_path, secrets)
    store.read_extension_control_authority(catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest)
    secrets.fail_anchor_set_number = secrets.anchor_set_count + 2
    with pytest.raises(ExtensionControlAuthorityError, match="final anchor"):
        _commit(store)
    with store._connect() as connection:
        premature_events = connection.execute(
            "select count(*) from guard_cloud_events where event_type = 'policy.changed'"
        ).fetchone()[0]
    assert premature_events == 0

    interrupted = store.read_extension_control_authority(
        catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest
    )
    assert interrupted.health is AuthorityHealth.RECOVERY_REQUIRED
    recovered = store.recover_extension_control_authority(
        catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest
    )
    assert recovered.health is AuthorityHealth.PROTECTED
    assert recovered.revision == 1
    assert recovered.layers == (_disabled_layer(),)
    with store._connect() as connection:
        recovered_events = connection.execute(
            "select count(*) from guard_cloud_events where event_type = 'policy.changed'"
        ).fetchone()[0]
    assert recovered_events == 1


def test_transition_records_are_purpose_separated_and_replay_safe(tmp_path: Path) -> None:
    secrets = MemorySecretStore()
    store = _store(tmp_path, secrets)
    store.read_extension_control_authority(catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest)
    _commit(store)
    replay = store.commit_extension_control_layers(
        (_disabled_layer(),),
        catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
        actor_id="local-admin",
        expected_revision=0,
        idempotency_key="change-1",
        nonce="nonce-change-1",
        proof=_proof(
            store,
            (_disabled_layer(),),
            revision=0,
            key="change-1",
            actor_id="local-admin",
            nonce="nonce-change-1",
        ),
    )
    assert replay.revision == 1

    with store._connect() as connection:
        row = connection.execute(
            "select transition_json, transition_mac from extension_control_authority_transition where revision = 1"
        ).fetchone()
        payload = json.loads(row["transition_json"])
        payload["purpose"] = "extension-control.snapshot"
        connection.execute(
            "update extension_control_authority_transition set transition_json = ? where revision = 1",
            (json.dumps(payload, sort_keys=True, separators=(",", ":")),),
        )
    tampered = store.read_extension_control_authority(catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest)
    assert tampered.health is AuthorityHealth.TAMPERED
