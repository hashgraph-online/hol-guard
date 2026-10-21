"""Schema compatibility and single-use authority proofs."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import cast

import pytest

from codex_plugin_scanner.guard import store_extension_control_authority_schema as authority_schema
from codex_plugin_scanner.guard.config import load_guard_config, update_guard_settings
from codex_plugin_scanner.guard.runtime.command_extensions import (
    BUILT_IN_COMMAND_EXTENSION_REGISTRY,
)
from codex_plugin_scanner.guard.runtime.extension_control_authority import (
    AuthorityHealth,
    ExtensionControlAuthorityError,
    ExtensionControlAuthorityView,
)
from codex_plugin_scanner.guard.runtime.extension_control_contract import (
    ControlLayerKind,
    ControlSurface,
)
from codex_plugin_scanner.guard.store import GuardStore

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


def test_v1_install_migrates_without_enrolling_or_changing_behavior(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    checksum_v1 = cast(str, vars(authority_schema)["_SCHEMA_CHECKSUM_V1"])
    with sqlite3.connect(guard_home / "guard.db") as connection:
        connection.execute(
            """
            create table extension_control_schema_migration (
                singleton integer primary key check (singleton = 1),
                version integer not null,
                checksum text not null
            )
            """
        )
        connection.execute(
            "insert into extension_control_schema_migration (singleton, version, checksum) values (1, 1, ?)",
            (checksum_v1,),
        )
    store = GuardStore(guard_home)

    view = store.read_extension_control_authority(catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest)
    with store._connect() as connection:
        version = connection.execute(
            "select version from extension_control_schema_migration where singleton = 1"
        ).fetchone()[0]
        snapshots = connection.execute("select count(*) from extension_control_authority_snapshot").fetchone()[0]

    assert version == authority_schema.EXTENSION_CONTROL_SCHEMA_VERSION
    assert snapshots == 0
    assert view.health is AuthorityHealth.UNENROLLED


def test_existing_settings_survive_authority_schema_migration_and_enrollment(tmp_path: Path) -> None:
    update_guard_settings(tmp_path, {"mode": "enforce"})
    before = load_guard_config(tmp_path)
    assert not (tmp_path / "guard.db").exists()

    store = _store(tmp_path, MemorySecretStore())
    _commit(store)
    after = load_guard_config(tmp_path)
    authority = store.read_extension_control_authority(
        catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest
    )

    assert after.mode == before.mode
    assert authority.health is AuthorityHealth.PROTECTED
    assert authority.revision == 1


def test_extension_control_schema_rejects_future_or_gapped_versions(tmp_path: Path) -> None:
    secrets = MemorySecretStore()
    store = _store(tmp_path, secrets)
    with store._connect() as connection:
        connection.execute("update extension_control_schema_migration set version = 99 where singleton = 1")
    view = store.read_extension_control_authority(catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest)

    assert view.health is AuthorityHealth.DEGRADED_UNACKNOWLEDGED
    with pytest.raises(ExtensionControlAuthorityError, match="schema"):
        _commit(store)


def test_incompatible_extension_schema_does_not_brick_store_open(tmp_path: Path) -> None:
    secrets = MemorySecretStore()
    store = _store(tmp_path, secrets)
    with store._connect() as connection:
        connection.execute("update extension_control_schema_migration set version = 99 where singleton = 1")

    opened = GuardStore(tmp_path, prime_policy_integrity=False)
    opened._extension_control_authority_secret_store = secrets

    assert opened.list_policy_decisions() == []


def test_non_protected_authority_requires_exact_trusted_surface_enum() -> None:
    digest = BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest
    view = ExtensionControlAuthorityView(AuthorityHealth.TAMPERED, 0, digest, ())

    raw = view.layers_for(cast(ControlSurface, "trusted-local-proof"))
    trusted = view.layers_for(ControlSurface.TRUSTED_LOCAL_PROOF)

    assert len(raw) == 1
    assert raw[0].kind is ControlLayerKind.LOCAL_ADMIN
    assert raw[0].global_lockdown is True
    assert trusted == ()


def test_transition_private_values_and_authority_secrets_never_enter_sqlite(tmp_path: Path) -> None:
    secrets = MemorySecretStore()
    store = _store(tmp_path, secrets)
    store.read_extension_control_authority(catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest)
    _commit(store, actor_id="private-actor")

    with store._connect() as connection:
        rows = [
            *connection.execute("select * from extension_control_authority_snapshot").fetchall(),
            *connection.execute("select * from extension_control_authority_transition").fetchall(),
        ]
    database_dump = repr([tuple(row) for row in rows])

    for private_value in ("private-actor", "change-1", "nonce-change-1", *secrets.values.values()):
        assert private_value not in database_dump


def test_idempotency_key_cannot_replay_different_transition(tmp_path: Path) -> None:
    secrets = MemorySecretStore()
    store = _store(tmp_path, secrets)
    store.read_extension_control_authority(catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest)
    _commit(store)

    with pytest.raises(ExtensionControlAuthorityError, match="idempotency key request mismatch"):
        store.commit_extension_control_layers(
            (),
            catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
            actor_id="different-actor",
            expected_revision=0,
            idempotency_key="change-1",
            nonce="different-nonce",
            proof=_proof(
                store,
                (),
                revision=0,
                key="change-1",
                actor_id="different-actor",
                nonce="different-nonce",
            ),
        )


def test_oversized_persisted_layers_fail_closed_without_deserialization(tmp_path: Path) -> None:
    secrets = MemorySecretStore()
    store = _store(tmp_path, secrets)
    store.read_extension_control_authority(catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest)
    oversized = "x" * (256 * 1024 + 1)
    with store._connect() as connection:
        connection.execute(
            "update extension_control_authority_snapshot set layers_json = ? where singleton = 1",
            (oversized,),
        )

    view = store.read_extension_control_authority(catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest)

    assert view.health is AuthorityHealth.TAMPERED


def test_authority_proof_is_consumed_once_and_only_private_hash_is_persisted(tmp_path: Path) -> None:
    secrets = MemorySecretStore()
    store = _store(tmp_path, secrets)
    digest = BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest
    store.read_extension_control_authority(catalog_digest=digest)
    layers = (_disabled_layer(),)
    proof = _proof(
        store,
        layers,
        revision=0,
        key="change-proof",
        actor_id="local-admin",
        nonce="nonce-proof",
    )

    committed = store.commit_extension_control_layers(
        layers,
        catalog_digest=digest,
        actor_id="local-admin",
        expected_revision=0,
        idempotency_key="change-proof",
        nonce="nonce-proof",
        proof=proof,
    )

    assert committed.revision == 1
    with store._connect() as connection:
        row = connection.execute(
            "select proof_id_hash, mutation_digest, transition_revision, consumed_at "
            "from extension_control_authority_proof"
        ).fetchone()
    assert row is not None
    assert row["proof_id_hash"] != proof.proof_id
    assert row["mutation_digest"] == proof.canonical_diff_digest
    assert row["transition_revision"] == 1
    assert row["consumed_at"] is not None

    with pytest.raises(ExtensionControlAuthorityError, match="proof replay"):
        store.commit_extension_control_layers(
            layers,
            catalog_digest=digest,
            actor_id="local-admin",
            expected_revision=0,
            idempotency_key="change-proof",
            nonce="nonce-proof",
            proof=proof,
        )


def test_mismatched_authority_proof_cannot_create_transition(tmp_path: Path) -> None:
    secrets = MemorySecretStore()
    store = _store(tmp_path, secrets)
    digest = BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest
    store.read_extension_control_authority(catalog_digest=digest)
    proof = _proof(
        store,
        (),
        revision=0,
        key="change-mismatch",
        actor_id="local-admin",
        nonce="nonce-mismatch",
    )

    with pytest.raises(PermissionError, match="does not match mutation"):
        store.commit_extension_control_layers(
            (_disabled_layer(),),
            catalog_digest=digest,
            actor_id="local-admin",
            expected_revision=0,
            idempotency_key="change-mismatch",
            nonce="nonce-mismatch",
            proof=proof,
        )

    with store._connect() as connection:
        assert connection.execute("select count(*) from extension_control_authority_transition").fetchone()[0] == 0
        assert connection.execute("select count(*) from extension_control_authority_proof").fetchone()[0] == 0


def test_failed_proof_reservation_preserves_grant_for_retry(tmp_path: Path) -> None:
    secrets = MemorySecretStore()
    store = _store(tmp_path, secrets)
    digest = BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest
    store.read_extension_control_authority(catalog_digest=digest)
    layers = (_disabled_layer(),)
    proof = _proof(
        store,
        layers,
        revision=0,
        key="change-reservation-retry",
        actor_id="local-admin",
        nonce="nonce-reservation-retry",
    )
    with store._connect() as connection:
        connection.execute(
            """
            create trigger fail_extension_control_proof_reservation
            before insert on extension_control_authority_proof
            begin
                select raise(abort, 'injected proof reservation failure');
            end
            """
        )

    with pytest.raises(sqlite3.IntegrityError, match="injected proof reservation failure"):
        store.commit_extension_control_layers(
            layers,
            catalog_digest=digest,
            actor_id="local-admin",
            expected_revision=0,
            idempotency_key="change-reservation-retry",
            nonce="nonce-reservation-retry",
            proof=proof,
        )

    with store._connect() as connection:
        connection.execute("drop trigger fail_extension_control_proof_reservation")
        assert connection.execute("select count(*) from extension_control_authority_proof").fetchone()[0] == 0
        assert connection.execute("select count(*) from extension_control_authority_transition").fetchone()[0] == 0

    committed = store.commit_extension_control_layers(
        layers,
        catalog_digest=digest,
        actor_id="local-admin",
        expected_revision=0,
        idempotency_key="change-reservation-retry",
        nonce="nonce-reservation-retry",
        proof=proof,
    )
    assert committed.revision == 1
