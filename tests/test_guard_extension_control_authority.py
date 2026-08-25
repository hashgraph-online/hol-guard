from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
from dataclasses import replace
from pathlib import Path
from typing import cast

import pytest

from codex_plugin_scanner.guard import store_extension_control_authority_schema as authority_schema
from codex_plugin_scanner.guard.approval_gate import ApprovalGateInput, update_settings
from codex_plugin_scanner.guard.config import load_guard_config, update_guard_settings
from codex_plugin_scanner.guard.extension_control_events import extension_control_change_payload
from codex_plugin_scanner.guard.runtime.command_extensions import (
    BUILT_IN_COMMAND_EXTENSION_REGISTRY,
    CommandSafetyExtensionRegistry,
)
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
    ExtensionControlEnrollment,
    ExtensionControlEnrollmentProof,
    ExtensionControlMutation,
    ExtensionControlProof,
    issue_extension_control_enrollment_proof,
    issue_extension_control_proof,
)
from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.store_base import (
    EncryptedFileSecretStore,
    MigratingFallbackSecretStore,
    SystemKeyringSecretStore,
)

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


@pytest.fixture(autouse=True)
def _allow_local_terminal_confirmation(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.runtime.extension_control_proof._require_local_terminal_confirmation",
        lambda _enrollment: None,
    )


def _store(
    tmp_path: Path,
    secrets: MemorySecretStore,
    *,
    enroll: bool = True,
) -> GuardStore:
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
    if enroll:
        _enroll(store)
    return store


def test_authenticated_recovery_rebuilds_unverifiable_authority(tmp_path: Path) -> None:
    secrets = MemorySecretStore()
    store = _store(tmp_path, secrets)
    with store._connect() as connection:
        connection.execute(
            "update extension_control_authority_snapshot set snapshot_digest = ? where singleton = 1",
            ("f" * 64,),
        )

    assert (
        store.read_extension_control_authority(catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest).health
        is AuthorityHealth.TAMPERED
    )

    repaired = store.recover_extension_control_authority(
        catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest
    )

    assert repaired.health is AuthorityHealth.PROTECTED
    assert repaired.revision == 0
    assert repaired.layers == ()
    assert (
        store.read_extension_control_authority(catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest).health
        is AuthorityHealth.PROTECTED
    )


def test_authenticated_recovery_rebuilds_snapshot_with_invalid_mac(tmp_path: Path) -> None:
    secrets = MemorySecretStore()
    store = _store(tmp_path, secrets)
    with store._connect() as connection:
        connection.execute(
            "update extension_control_authority_snapshot set snapshot_mac = ? where singleton = 1",
            ("invalid",),
        )

    repaired = store.recover_extension_control_authority(
        catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest
    )

    assert repaired.health is AuthorityHealth.PROTECTED
    assert repaired.revision == 0
    assert repaired.layers == ()
    with store._connect() as connection:
        event = connection.execute(
            "select payload_json from guard_events where event_name = ? order by event_id desc limit 1",
            ("extension_control_authority_reset",),
        ).fetchone()
    assert event is not None
    payload = json.loads(event["payload_json"])
    assert payload["reason"] == "authenticated-recovery-unverifiable"
    assert payload["previous_revision"] == 0
    assert payload["previous_catalog_digest"] == BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest
    assert payload["previous_layers_bytes"] > 0
    with store._connect() as connection:
        archive = connection.execute(
            "select archive_id, snapshot_row_json from extension_control_authority_recovery_archive "
            "where archive_id = ?",
            (payload["archive_id"],),
        ).fetchone()
    assert archive is not None
    assert json.loads(archive["snapshot_row_json"])["catalog_digest"] == payload["previous_catalog_digest"]


def test_recovery_archives_authority_before_bootstrap_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secrets = MemorySecretStore()
    store = _store(tmp_path, secrets)
    original_digest = BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest
    store.read_extension_control_authority(catalog_digest=original_digest)
    _commit(store)
    with store._connect() as connection:
        connection.execute(
            "update extension_control_authority_snapshot set snapshot_mac = ? where singleton = 1",
            ("invalid",),
        )
    monkeypatch.setattr(
        store,
        "_bootstrap_extension_control_authority",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("injected bootstrap failure")),
    )

    with pytest.raises(RuntimeError, match="injected bootstrap failure"):
        store.recover_extension_control_authority(catalog_digest=original_digest)

    with store._connect() as connection:
        archive = connection.execute(
            "select snapshot_row_json, transition_rows_json from extension_control_authority_recovery_archive"
        ).fetchone()
        event = connection.execute(
            "select payload_json from guard_events where event_name = 'extension_control_authority_reset'"
        ).fetchone()
    assert archive is not None
    assert json.loads(archive["snapshot_row_json"])["revision"] == 1
    assert len(json.loads(archive["transition_rows_json"])) == 1
    assert event is not None


@pytest.mark.parametrize("missing_part", ("snapshot", "anchor", "key"))
def test_authenticated_recovery_rebuilds_incomplete_authority(tmp_path: Path, missing_part: str) -> None:
    secrets = MemorySecretStore()
    store = _store(tmp_path, secrets)
    if missing_part == "snapshot":
        with store._connect() as connection:
            connection.execute("delete from extension_control_authority_snapshot")
    else:
        suffix = ":anchor" if missing_part == "anchor" else ":authentication-key"
        secret_id = next(secret_id for secret_id in secrets.values if secret_id.endswith(suffix))
        secrets.delete_secret(secret_id)

    repaired = store.recover_extension_control_authority(
        catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest
    )

    assert repaired.health is AuthorityHealth.PROTECTED
    assert repaired.revision == 0
    assert repaired.layers == ()


def _enrollment_proof(
    store: GuardStore,
    *,
    actor_id: str = "local-admin",
    nonce: str = "enrollment-nonce",
) -> ExtensionControlEnrollmentProof:
    enrollment = ExtensionControlEnrollment(
        catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
        actor_id=actor_id,
        nonce=nonce,
    )
    return issue_extension_control_enrollment_proof(
        store.guard_home,
        enrollment,
        approval_gate_input=ApprovalGateInput(password=_PASSWORD),
        session_nonce=f"session-{nonce}",
    )


def _enroll(
    store: GuardStore,
    *,
    actor_id: str = "local-admin",
    nonce: str = "enrollment-nonce",
) -> ExtensionControlAuthorityView:
    return store.enroll_extension_control_authority(
        catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
        actor_id=actor_id,
        nonce=nonce,
        proof=_enrollment_proof(store, actor_id=actor_id, nonce=nonce),
    )


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


def _upgraded_registry(*, remove_first_extension: bool = False) -> CommandSafetyExtensionRegistry:
    extensions = BUILT_IN_COMMAND_EXTENSION_REGISTRY.extensions
    if remove_first_extension:
        return CommandSafetyExtensionRegistry(extensions[1:])
    return CommandSafetyExtensionRegistry(
        (replace(extensions[0], description=f"{extensions[0].description} Updated."), *extensions[1:])
    )


def _expanded_permission_registry() -> tuple[CommandSafetyExtensionRegistry, str]:
    extensions = BUILT_IN_COMMAND_EXTENSION_REGISTRY.extensions
    extension = extensions[0]
    permission = extension.permissions[0]
    expanded_permission = replace(
        permission,
        typed_capabilities=(*permission.typed_capabilities, "test.expanded-capability"),
    )
    expanded_extension = replace(
        extension,
        permissions=(expanded_permission, *extension.permissions[1:]),
    )
    return CommandSafetyExtensionRegistry((expanded_extension, *extensions[1:])), permission.permission_id


def _rule_version_registry() -> tuple[CommandSafetyExtensionRegistry, str]:
    extensions = BUILT_IN_COMMAND_EXTENSION_REGISTRY.extensions
    extension = extensions[0]
    rule = extension.rules[0]
    versioned_rule = replace(rule, rule_version="99.0.0")
    versioned_extension = replace(extension, rules=(versioned_rule, *extension.rules[1:]))
    return CommandSafetyExtensionRegistry((versioned_extension, *extensions[1:])), extension.permissions[
        0
    ].permission_id


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


def _commit_enabled_permission(store: GuardStore, permission_id: str, *, key: str) -> None:
    layer = ExtensionControlLayer(
        schema_version=CONTROL_SCHEMA_VERSION,
        kind=ControlLayerKind.LOCAL_ADMIN,
        catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
        global_lockdown=False,
        controls=(
            ExtensionControl(
                ControlTarget(ControlTargetKind.PERMISSION, permission_id),
                ControlState.ENABLED,
            ),
        ),
    )
    nonce = f"nonce-{key}"
    store.commit_extension_control_layers(
        (layer,),
        catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
        actor_id="local-admin",
        expected_revision=0,
        idempotency_key=key,
        nonce=nonce,
        proof=_proof(
            store,
            (layer,),
            revision=0,
            key=key,
            actor_id="local-admin",
            nonce=nonce,
        ),
    )


def test_first_enrollment_requires_one_trusted_local_proof(tmp_path: Path) -> None:
    secrets = MemorySecretStore()
    store = _store(tmp_path, secrets, enroll=False)
    digest = BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest

    initial = store.read_extension_control_authority(catalog_digest=digest)
    assert initial.health is AuthorityHealth.UNENROLLED
    assert initial.revision == 0
    assert initial.layers == ()
    assert secrets.values == {}

    proof = _enrollment_proof(store)
    enrolled = store.enroll_extension_control_authority(
        catalog_digest=digest,
        actor_id="local-admin",
        nonce="enrollment-nonce",
        proof=proof,
    )
    assert enrolled.health is AuthorityHealth.PROTECTED
    persisted_database = (tmp_path / "guard.db").read_bytes()
    for private_value in (
        proof.proof_id,
        proof.grant.grant_id,
        proof.actor_id,
        proof.nonce,
        proof.session_nonce,
    ):
        assert private_value.encode() not in persisted_database

    with pytest.raises(ExtensionControlAuthorityError, match="already enrolled"):
        store.enroll_extension_control_authority(
            catalog_digest=digest,
            actor_id="local-admin",
            nonce="second-enrollment",
            proof=_enrollment_proof(store, nonce="second-enrollment"),
        )


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


def test_authenticated_catalog_upgrade_preserves_controls_and_records_provenance(tmp_path: Path) -> None:
    secrets = MemorySecretStore()
    store = _store(tmp_path, secrets)
    original_digest = BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest
    store.read_extension_control_authority(catalog_digest=original_digest)
    _commit(store)
    upgraded_registry = _upgraded_registry()
    upgraded_digest = upgraded_registry.catalog_digest

    upgraded = store.read_extension_control_authority_for_registry(upgraded_registry)

    assert upgraded.health is AuthorityHealth.PROTECTED
    assert upgraded.revision == 2
    assert len(upgraded.layers) == 1
    assert upgraded.layers[0].catalog_digest == upgraded_digest
    assert upgraded.layers[0].controls == _disabled_layer().controls
    with store._connect() as connection:
        event = connection.execute(
            "select payload_json from guard_events where event_name = ? order by event_id desc limit 1",
            ("extension_control_authority_catalog_migrated",),
        ).fetchone()
        transition = connection.execute(
            "select previous_revision, catalog_digest, phase from extension_control_authority_transition "
            "where revision = 2"
        ).fetchone()
    assert event is not None
    assert json.loads(event["payload_json"]) == {
        "previous_revision": 1,
        "revision": 2,
        "previous_catalog_digest": original_digest,
        "catalog_digest": upgraded_digest,
        "layer_count": 1,
        "control_count": 1,
        "retired_target_count": 0,
        "retired_target_ids": [],
    }
    assert dict(transition) == {
        "previous_revision": 1,
        "catalog_digest": upgraded_digest,
        "phase": AuthorityPhase.COMMITTED.value,
    }


def test_catalog_digest_change_requires_trusted_migration_boundary(tmp_path: Path) -> None:
    secrets = MemorySecretStore()
    store = _store(tmp_path, secrets)
    original_digest = BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest
    store.read_extension_control_authority(catalog_digest=original_digest)
    _commit(store)

    rejected = store.read_extension_control_authority(catalog_digest="c" * 64)

    assert rejected.health is AuthorityHealth.TAMPERED
    with store._connect() as connection:
        snapshot = connection.execute(
            "select revision, catalog_digest from extension_control_authority_snapshot where singleton = 1"
        ).fetchone()
        migration_events = connection.execute(
            "select count(*) from guard_events where event_name = ?",
            ("extension_control_authority_catalog_migrated",),
        ).fetchone()[0]
    assert dict(snapshot) == {"revision": 1, "catalog_digest": original_digest}
    assert migration_events == 0


def test_catalog_upgrade_retires_removed_targets_with_provenance(tmp_path: Path) -> None:
    secrets = MemorySecretStore()
    store = _store(tmp_path, secrets)
    original_digest = BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest
    removed_target = _disabled_layer().controls[0].target.target_id
    store.read_extension_control_authority(catalog_digest=original_digest)
    _commit(store)
    upgraded_registry = _upgraded_registry(remove_first_extension=True)

    upgraded = store.read_extension_control_authority_for_registry(upgraded_registry)

    assert upgraded.health is AuthorityHealth.PROTECTED
    assert upgraded.revision == 2
    assert upgraded.layers[0].controls == ()
    with store._connect() as connection:
        event = connection.execute(
            "select payload_json from guard_events where event_name = ? order by event_id desc limit 1",
            ("extension_control_authority_catalog_migrated",),
        ).fetchone()
    assert event is not None
    payload = json.loads(event["payload_json"])
    assert payload["retired_target_count"] == 1
    assert payload["retired_target_ids"] == [removed_target]


def test_catalog_upgrade_retires_enabled_target_when_contract_expands(tmp_path: Path) -> None:
    secrets = MemorySecretStore()
    store = _store(tmp_path, secrets)
    store.read_extension_control_authority_for_registry(BUILT_IN_COMMAND_EXTENSION_REGISTRY)
    upgraded_registry, permission_id = _expanded_permission_registry()
    _commit_enabled_permission(store, permission_id, key="enable-before-expansion")

    upgraded = store.read_extension_control_authority_for_registry(upgraded_registry)

    assert upgraded.health is AuthorityHealth.PROTECTED
    assert upgraded.layers[0].controls == ()
    with store._connect() as connection:
        event = connection.execute(
            "select payload_json from guard_events where event_name = ? order by event_id desc limit 1",
            ("extension_control_authority_catalog_migrated",),
        ).fetchone()
    assert event is not None
    payload = json.loads(event["payload_json"])
    assert payload["retired_target_ids"] == [permission_id]


def test_catalog_upgrade_preserves_enabled_controls_when_previous_manifest_is_missing(
    tmp_path: Path,
) -> None:
    secrets = MemorySecretStore()
    store = _store(tmp_path, secrets)
    store.read_extension_control_authority_for_registry(BUILT_IN_COMMAND_EXTENSION_REGISTRY)
    permission_id = BUILT_IN_COMMAND_EXTENSION_REGISTRY.extensions[0].permissions[0].permission_id
    _commit_enabled_permission(store, permission_id, key="enable-before-missing-manifest")
    with store._connect() as connection:
        connection.execute("delete from extension_control_catalog_manifest")

    upgraded = store.read_extension_control_authority_for_registry(_upgraded_registry())

    assert upgraded.health is AuthorityHealth.PROTECTED
    assert upgraded.layers[0].controls[0].target.target_id == permission_id
    assert upgraded.layers[0].controls[0].state is ControlState.ENABLED


def test_catalog_upgrade_preserves_enabled_git_allows_when_unrelated_catalog_grows(
    tmp_path: Path,
) -> None:
    secrets = MemorySecretStore()
    store = _store(tmp_path, secrets)
    git = next(
        extension
        for extension in BUILT_IN_COMMAND_EXTENSION_REGISTRY.extensions
        if extension.extension_id == "command.git"
    )
    permission_id = next(permission.permission_id for permission in git.permissions if permission.configurable)
    store.read_extension_control_authority_for_registry(BUILT_IN_COMMAND_EXTENSION_REGISTRY)
    _commit_enabled_permission(store, permission_id, key="enable-git-before-catalog-growth")

    upgraded = store.read_extension_control_authority_for_registry(_upgraded_registry())

    assert upgraded.health is AuthorityHealth.PROTECTED
    assert upgraded.layers[0].controls[0].target.target_id == permission_id
    assert upgraded.layers[0].controls[0].state is ControlState.ENABLED


def test_catalog_upgrade_preserves_enabled_target_for_description_only_change(tmp_path: Path) -> None:
    secrets = MemorySecretStore()
    store = _store(tmp_path, secrets)
    store.read_extension_control_authority_for_registry(BUILT_IN_COMMAND_EXTENSION_REGISTRY)
    permission_id = BUILT_IN_COMMAND_EXTENSION_REGISTRY.extensions[0].permissions[0].permission_id
    _commit_enabled_permission(store, permission_id, key="enable-before-copy-change")

    upgraded = store.read_extension_control_authority_for_registry(_upgraded_registry())

    assert upgraded.health is AuthorityHealth.PROTECTED
    assert upgraded.layers[0].controls[0].target.target_id == permission_id
    assert upgraded.layers[0].controls[0].state is ControlState.ENABLED


def test_catalog_upgrade_retires_enabled_target_when_rule_version_changes(tmp_path: Path) -> None:
    secrets = MemorySecretStore()
    store = _store(tmp_path, secrets)
    store.read_extension_control_authority_for_registry(BUILT_IN_COMMAND_EXTENSION_REGISTRY)
    upgraded_registry, permission_id = _rule_version_registry()
    _commit_enabled_permission(store, permission_id, key="enable-before-rule-version-change")

    upgraded = store.read_extension_control_authority_for_registry(upgraded_registry)

    assert upgraded.health is AuthorityHealth.PROTECTED
    assert upgraded.layers[0].controls == ()


def test_catalog_manifest_tamper_is_detected_immediately(tmp_path: Path) -> None:
    secrets = MemorySecretStore()
    store = _store(tmp_path, secrets)
    protected = store.read_extension_control_authority_for_registry(BUILT_IN_COMMAND_EXTENSION_REGISTRY)
    assert protected.health is AuthorityHealth.PROTECTED
    with store._connect() as connection:
        connection.execute(
            "update extension_control_catalog_manifest set record_mac = ? where catalog_digest = ?",
            ("0" * 64, BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest),
        )

    tampered = store.read_extension_control_authority_for_registry(BUILT_IN_COMMAND_EXTENSION_REGISTRY)

    assert tampered.health is AuthorityHealth.TAMPERED


def test_catalog_manifest_is_stable_across_python_hash_seeds() -> None:
    script = """
import hashlib
import json
from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.store import GuardStore
manifest = GuardStore._catalog_target_manifest(BUILT_IN_COMMAND_EXTENSION_REGISTRY)
payload = json.dumps(manifest, sort_keys=True, separators=(\",\", \":\"))
print(hashlib.sha256(payload.encode()).hexdigest())
"""
    digests = set()
    for seed in ("1", "2", "3", "4"):
        environment = dict(os.environ)
        environment["PYTHONHASHSEED"] = seed
        environment["PYTHONPATH"] = str(Path(__file__).parents[1] / "src")
        completed = subprocess.run(
            [sys.executable, "-c", script],
            check=True,
            capture_output=True,
            text=True,
            env=environment,
        )
        digests.add(completed.stdout.strip())
    assert len(digests) == 1


def test_catalog_upgrade_provenance_survives_final_anchor_failure(tmp_path: Path) -> None:
    secrets = MemorySecretStore()
    store = _store(tmp_path, secrets)
    original_digest = BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest
    store.read_extension_control_authority(catalog_digest=original_digest)
    _commit(store)
    upgraded_registry = _upgraded_registry()
    upgraded_digest = upgraded_registry.catalog_digest
    secrets.fail_anchor_set_number = secrets.anchor_set_count + 2

    interrupted = store.read_extension_control_authority_for_registry(upgraded_registry)

    assert interrupted.health is AuthorityHealth.DEGRADED_UNACKNOWLEDGED
    with store._connect() as connection:
        event = connection.execute(
            "select payload_json from guard_events where event_name = ? order by event_id desc limit 1",
            ("extension_control_authority_catalog_migrated",),
        ).fetchone()
    assert event is not None
    assert json.loads(event["payload_json"])["catalog_digest"] == upgraded_digest
    secrets.fail_anchor_set_number = None
    recovered = store.recover_extension_control_authority(catalog_digest=upgraded_digest)
    assert recovered.health is AuthorityHealth.PROTECTED
    assert recovered.layers[0].controls == _disabled_layer().controls


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


def test_unavailable_system_keyring_uses_owner_only_vault(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(
        SystemKeyringSecretStore,
        "get_secret",
        lambda _self, _secret_id: (_ for _ in ()).throw(RuntimeError("keyring unavailable")),
    )
    monkeypatch.setattr(
        SystemKeyringSecretStore,
        "set_secret",
        lambda _self, _secret_id, _value: (_ for _ in ()).throw(RuntimeError("keyring unavailable")),
    )
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

    assert isinstance(store._secret_store(), MigratingFallbackSecretStore)
    assert _enroll(store).health is AuthorityHealth.PROTECTED

    restarted = GuardStore(tmp_path, prime_policy_integrity=False)
    view = restarted.read_extension_control_authority(catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest)
    assert view.health is AuthorityHealth.PROTECTED
    secrets_dir = tmp_path / "secrets"
    if os.name != "nt":
        assert secrets_dir.stat().st_mode & 0o777 == 0o700
        assert all(path.stat().st_mode & 0o777 == 0o600 for path in secrets_dir.iterdir() if path.is_file())


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

    def tracked_interactive_read(_self: SystemKeyringSecretStore, secret_id: str) -> str | None:
        interactive_reads.append(secret_id)
        return legacy_secrets.get_secret(secret_id)

    def tracked_bounded_read(
        _self: SystemKeyringSecretStore,
        secret_id: str,
        *,
        timeout_seconds: float = 0.0,
    ) -> str | None:
        _ = timeout_seconds
        bounded_reads.append(secret_id)
        return legacy_secrets.get_secret(secret_id)

    monkeypatch.setattr(SystemKeyringSecretStore, "get_secret", tracked_interactive_read)
    monkeypatch.setattr(SystemKeyringSecretStore, "get_secret_with_timeout", tracked_bounded_read)
    explicit_store = GuardStore(tmp_path, prime_policy_integrity=False, allow_system_keyring=True)

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

    assert view.health is AuthorityHealth.TAMPERED
    assert view.layers == ()
    assert view.layers_for(ControlSurface.COMMAND_EVALUATION)[0].global_lockdown is True


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


def test_control_change_queues_privacy_safe_append_only_cloud_event(tmp_path: Path) -> None:
    secrets = MemorySecretStore()
    store = _store(tmp_path, secrets)

    _commit(store, actor_id="private-admin-identity")

    with store._connect() as connection:
        rows = connection.execute(
            "select event_type, payload_json from guard_cloud_events where event_type = 'policy.changed'"
        ).fetchall()
    assert len(rows) == 1
    envelope = json.loads(str(rows[0]["payload_json"]))
    assert envelope["source"] == "policy"
    payload = envelope["payload"]
    assert payload["schema"] == "guard.extension-control-authority-change.v1"
    assert payload["revision"] == 1
    assert payload["previousRevision"] == 0
    assert payload["disabledExtensionCount"] == 1
    assert payload["blockSource"] == "extension-control-authority"
    serialized = json.dumps(envelope)
    assert "private-admin-identity" not in serialized
    assert "nonce-change-1" not in serialized
    assert _PASSWORD not in serialized


def test_control_change_payload_counts_extension_and_permission_blocks() -> None:
    extension = BUILT_IN_COMMAND_EXTENSION_REGISTRY.extensions[0]
    permission = extension.permissions[0]
    layer = ExtensionControlLayer(
        schema_version=CONTROL_SCHEMA_VERSION,
        kind=ControlLayerKind.LOCAL_ADMIN,
        catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
        global_lockdown=False,
        controls=(
            ExtensionControl(
                ControlTarget(ControlTargetKind.EXTENSION, extension.extension_id),
                ControlState.DISABLED,
            ),
            ExtensionControl(
                ControlTarget(ControlTargetKind.PERMISSION, permission.permission_id),
                ControlState.DISABLED,
            ),
        ),
    )

    payload = extension_control_change_payload(
        revision=2,
        previous_revision=1,
        layers=(layer,),
    )

    assert payload["disabledExtensionCount"] == 1
    assert payload["disabledPermissionCount"] == 1


def test_authenticated_history_returns_only_verified_prior_device_layers(tmp_path: Path) -> None:
    secrets = MemorySecretStore()
    store = _store(tmp_path, secrets)
    first = (_disabled_layer(),)
    committed = store.commit_extension_control_layers(
        first,
        catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
        actor_id="history-test",
        expected_revision=0,
        idempotency_key="history-1",
        nonce="history-nonce-1",
        proof=_proof(store, first, revision=0, key="history-1", actor_id="history-test", nonce="history-nonce-1"),
    )
    assert committed.revision == 1
    second: tuple[ExtensionControlLayer, ...] = ()
    committed = store.commit_extension_control_layers(
        second,
        catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
        actor_id="history-test",
        expected_revision=1,
        idempotency_key="history-2",
        nonce="history-nonce-2",
        proof=_proof(store, second, revision=1, key="history-2", actor_id="history-test", nonce="history-nonce-2"),
    )
    assert committed.revision == 2
    history = store.list_extension_control_authority_history(
        catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
        limit=20,
    )
    assert [item["revision"] for item in history] == [1]
    assert history[0]["layers"][0]["kind"] == "local-admin"
    encoded = json.dumps(history, sort_keys=True)
    for private_name in (
        "actor_id_hash",
        "idempotency_key_hash",
        "nonce_hash",
        "snapshot_mac",
        "transition_mac",
        "proof",
    ):
        assert private_name not in encoded


def test_authenticated_history_fails_closed_on_tampered_transition(tmp_path: Path) -> None:
    secrets = MemorySecretStore()
    store = _store(tmp_path, secrets)
    first = (_disabled_layer(),)
    _ = store.commit_extension_control_layers(
        first,
        catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
        actor_id="history-test",
        expected_revision=0,
        idempotency_key="history-tamper-1",
        nonce="history-tamper-nonce-1",
        proof=_proof(
            store, first, revision=0, key="history-tamper-1", actor_id="history-test", nonce="history-tamper-nonce-1"
        ),
    )
    second: tuple[ExtensionControlLayer, ...] = ()
    _ = store.commit_extension_control_layers(
        second,
        catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
        actor_id="history-test",
        expected_revision=1,
        idempotency_key="history-tamper-2",
        nonce="history-tamper-nonce-2",
        proof=_proof(
            store, second, revision=1, key="history-tamper-2", actor_id="history-test", nonce="history-tamper-nonce-2"
        ),
    )
    with store._connect() as connection:
        connection.execute(
            "update extension_control_authority_transition set transition_mac = ? where revision = 1", ("invalid",)
        )
    with pytest.raises(ExtensionControlAuthorityError):
        store.list_extension_control_authority_history(
            catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
            limit=20,
        )
