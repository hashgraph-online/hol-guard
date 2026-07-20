from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.runtime.extension_control_authority import (
    AuthorityHealth,
    AuthorityPhase,
    ExtensionControlAuthorityError,
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
from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.store_base import SystemKeyringSecretStore


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


def _commit(store: GuardStore, *, revision: int = 0, key: str = "change-1") -> None:
    store.commit_extension_control_layers(
        (_disabled_layer(),),
        catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
        actor_id="local-admin",
        expected_revision=revision,
        idempotency_key=key,
        nonce=f"nonce-{key}",
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
