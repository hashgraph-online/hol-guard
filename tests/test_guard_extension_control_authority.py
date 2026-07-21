from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import cast

import pytest

from codex_plugin_scanner.guard.approval_gate import ApprovalGateInput, update_settings
from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.runtime.extension_control_authority import (
    AuthorityHealth,
    AuthorityPhase,
    ExtensionControlAuthorityError,
    ExtensionControlAuthorityView,
)
from codex_plugin_scanner.guard.runtime.extension_control_contract import (
    CONTROL_SCHEMA_VERSION,
    ControlLayerKind,
    ControlState,
    ControlSurface,
    ControlTarget,
    ControlTargetKind,
    ExtensionControl,
    ExtensionControlLayer,
)
from codex_plugin_scanner.guard.runtime.extension_control_proof import (
    ExtensionControlMutation,
    ExtensionControlProof,
    issue_extension_control_proof,
)
from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.store_base import SystemKeyringSecretStore

_PASSWORD = "correct horse battery staple"


class MemorySecretStore:
    def __init__(self) -> None:
        self.values: dict[str, str] = {}
        self.available = True
        self.anchor_set_count = 0
        self.fail_anchor_set_number: int | None = None

    def set_secret(self, secret_id: str, value: str) -> None:
        if not self.available:
            raise RuntimeError("credential store unavailable")
        if secret_id.endswith(":anchor"):
            self.anchor_set_count += 1
            if self.fail_anchor_set_number == self.anchor_set_count:
                raise RuntimeError("injected anchor failure")
        self.values[secret_id] = value

    def get_secret(self, secret_id: str) -> str | None:
        if not self.available:
            raise RuntimeError("credential store unavailable")
        return self.values.get(secret_id)

    def delete_secret(self, secret_id: str) -> None:
        if not self.available:
            raise RuntimeError("credential store unavailable")
        self.values.pop(secret_id, None)


def _store(tmp_path: Path, secrets: MemorySecretStore) -> GuardStore:
    store = GuardStore(tmp_path, prime_policy_integrity=False)
    update_settings(
        tmp_path,
        {
            "enabled": True,
            "new_password": _PASSWORD,
            "confirm_password": _PASSWORD,
            "cooldown_seconds": 0,
        },
    )
    store._extension_control_authority_secret_store = secrets
    return store


def _disabled_layer() -> ExtensionControlLayer:
    extension = BUILT_IN_COMMAND_EXTENSION_REGISTRY.extensions[0]
    return ExtensionControlLayer(
        schema_version=CONTROL_SCHEMA_VERSION,
        kind=ControlLayerKind.LOCAL_ADMIN,
        catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
        global_lockdown=False,
        controls=(
            ExtensionControl(
                ControlTarget(ControlTargetKind.EXTENSION, extension.extension_id),
                ControlState.DISABLED,
            ),
        ),
    )


def _proof(
    store: GuardStore,
    layers: tuple[ExtensionControlLayer, ...],
    *,
    revision: int,
    key: str,
    actor_id: str,
    nonce: str,
) -> ExtensionControlProof:
    return issue_extension_control_proof(
        store.guard_home,
        ExtensionControlMutation(
            previous_revision=revision,
            catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
            layers=layers,
            actor_id=actor_id,
            idempotency_key=key,
            nonce=nonce,
        ),
        approval_gate_input=ApprovalGateInput(password=_PASSWORD),
        session_nonce=f"session-{key}-{nonce}",
    )


def _commit(
    store: GuardStore,
    *,
    revision: int = 0,
    key: str = "change-1",
    actor_id: str = "local-admin",
) -> None:
    store.commit_extension_control_layers(
        (_disabled_layer(),),
        catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
        actor_id=actor_id,
        expected_revision=revision,
        idempotency_key=key,
        nonce=f"nonce-{key}",
        proof=_proof(
            store,
            (_disabled_layer(),),
            revision=revision,
            key=key,
            actor_id=actor_id,
            nonce=f"nonce-{key}",
        ),
    )


def test_bootstrap_occurs_only_when_database_and_anchor_are_both_absent(tmp_path: Path) -> None:
    secrets = MemorySecretStore()
    store = _store(tmp_path, secrets)

    initial = store.read_extension_control_authority(catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest)
    assert initial.health is AuthorityHealth.PROTECTED
    assert initial.revision == 0
    assert initial.layers == ()

    with store._connect() as connection:
        connection.execute("delete from extension_control_authority_snapshot")
    missing_database = store.read_extension_control_authority(
        catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest
    )
    assert missing_database.health is AuthorityHealth.TAMPERED
    assert missing_database.layers_for(ControlSurface.COMMAND_EVALUATION)[0].global_lockdown is True

    second_secrets = MemorySecretStore()
    second_store = _store(tmp_path / "both-missing", second_secrets)
    second_store.read_extension_control_authority(catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest)
    anchor_ref = next(secret_id for secret_id in second_secrets.values if secret_id.endswith(":anchor"))
    del second_secrets.values[anchor_ref]
    with second_store._connect() as connection:
        connection.execute("delete from extension_control_authority_snapshot")
    missing_both_with_existing_key = second_store.read_extension_control_authority(
        catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest
    )
    assert missing_both_with_existing_key.health is AuthorityHealth.TAMPERED
    assert anchor_ref not in second_secrets.values


def test_authenticated_snapshot_transition_and_anchor_detect_sqlite_tamper(tmp_path: Path) -> None:
    secrets = MemorySecretStore()
    store = _store(tmp_path, secrets)
    store.read_extension_control_authority(catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest)
    _commit(store)

    with store._connect() as connection:
        connection.execute(
            "update extension_control_authority_snapshot set layers_json = ? where singleton = 1",
            ("[]",),
        )
    view = store.read_extension_control_authority(catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest)
    assert view.health is AuthorityHealth.TAMPERED
    assert view.layers == ()


def test_authenticated_historical_transition_fields_detect_tamper(tmp_path: Path) -> None:
    secrets = MemorySecretStore()
    store = _store(tmp_path, secrets)
    store.read_extension_control_authority(catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest)
    _commit(store)
    store.commit_extension_control_layers(
        (),
        catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
        actor_id="local-admin",
        expected_revision=1,
        idempotency_key="change-2",
        nonce="nonce-change-2",
        proof=_proof(
            store,
            (),
            revision=1,
            key="change-2",
            actor_id="local-admin",
            nonce="nonce-change-2",
        ),
    )
    with store._connect() as connection:
        connection.execute(
            "update extension_control_authority_transition set layers_json = ? where revision = 1",
            ("[]",),
        )

    view = store.read_extension_control_authority(catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest)

    assert view.health is AuthorityHealth.TAMPERED


def test_database_rollback_against_monotonic_anchor_fails_closed(tmp_path: Path) -> None:
    secrets = MemorySecretStore()
    store = _store(tmp_path, secrets)
    store.read_extension_control_authority(catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest)
    with store._connect() as connection:
        original = dict(connection.execute("select * from extension_control_authority_snapshot").fetchone())
    _commit(store)
    with store._connect() as connection:
        connection.execute(
            """
            update extension_control_authority_snapshot
            set revision = ?, catalog_digest = ?, layers_json = ?, previous_digest = ?,
                snapshot_json = ?, snapshot_digest = ?, snapshot_mac = ?, committed_at = ?
            where singleton = 1
            """,
            (
                original["revision"],
                original["catalog_digest"],
                original["layers_json"],
                original["previous_digest"],
                original["snapshot_json"],
                original["snapshot_digest"],
                original["snapshot_mac"],
                original["committed_at"],
            ),
        )

    view = store.read_extension_control_authority(catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest)
    assert view.health is AuthorityHealth.TAMPERED


def test_credential_store_failure_requires_explicit_degraded_acknowledgement(tmp_path: Path) -> None:
    secrets = MemorySecretStore()
    store = _store(tmp_path, secrets)
    store.read_extension_control_authority(catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest)
    secrets.available = False

    degraded = store.read_extension_control_authority(catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest)
    assert degraded.health is AuthorityHealth.DEGRADED_UNACKNOWLEDGED
    assert degraded.layers_for(ControlSurface.COMMAND_EVALUATION)[0].global_lockdown is True
    assert degraded.layers_for(ControlSurface.TRUSTED_LOCAL_RECOVERY) == ()

    acknowledged = store.acknowledge_extension_control_degraded_mode()
    assert acknowledged.health is AuthorityHealth.DEGRADED_ACKNOWLEDGED
    with pytest.raises(ExtensionControlAuthorityError, match="unavailable"):
        _commit(store)


def test_unavailable_system_keyring_never_silently_falls_back(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        SystemKeyringSecretStore,
        "_is_available",
        classmethod(lambda cls: False),
    )
    store = GuardStore(tmp_path, prime_policy_integrity=False)

    view = store.read_extension_control_authority(catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest)

    assert view.health is AuthorityHealth.DEGRADED_UNACKNOWLEDGED
    assert view.layers_for(ControlSurface.COMMAND_EVALUATION)[0].global_lockdown is True


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
    assert count == 1


def test_recovery_finalizes_database_commit_when_final_anchor_write_failed(tmp_path: Path) -> None:
    secrets = MemorySecretStore()
    store = _store(tmp_path, secrets)
    store.read_extension_control_authority(catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest)
    secrets.fail_anchor_set_number = secrets.anchor_set_count + 2
    with pytest.raises(ExtensionControlAuthorityError, match="final anchor"):
        _commit(store)

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


def test_extension_control_schema_rejects_future_or_gapped_versions(tmp_path: Path) -> None:
    secrets = MemorySecretStore()
    store = _store(tmp_path, secrets)
    with store._connect() as connection:
        connection.execute("update extension_control_schema_migration set version = 99 where singleton = 1")
    with pytest.raises(ExtensionControlAuthorityError, match="schema"):
        store.read_extension_control_authority(catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest)


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


def test_prepared_transition_retries_with_same_reserved_proof(tmp_path: Path) -> None:
    secrets = MemorySecretStore()
    store = _store(tmp_path, secrets)
    digest = BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest
    store.read_extension_control_authority(catalog_digest=digest)
    layers = (_disabled_layer(),)
    proof = _proof(
        store,
        layers,
        revision=0,
        key="change-prepared-retry",
        actor_id="local-admin",
        nonce="nonce-prepared-retry",
    )
    secrets.fail_anchor_set_number = secrets.anchor_set_count + 1

    with pytest.raises(ExtensionControlAuthorityError, match="anchor unavailable"):
        store.commit_extension_control_layers(
            layers,
            catalog_digest=digest,
            actor_id="local-admin",
            expected_revision=0,
            idempotency_key="change-prepared-retry",
            nonce="nonce-prepared-retry",
            proof=proof,
        )

    committed = store.commit_extension_control_layers(
        layers,
        catalog_digest=digest,
        actor_id="local-admin",
        expected_revision=0,
        idempotency_key="change-prepared-retry",
        nonce="nonce-prepared-retry",
        proof=proof,
    )
    assert committed.revision == 1
