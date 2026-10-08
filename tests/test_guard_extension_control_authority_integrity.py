"""Catalog, rollback and vault integrity regressions."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.approval_gate import update_settings
from codex_plugin_scanner.guard.runtime.command_extensions import (
    BUILT_IN_COMMAND_EXTENSION_REGISTRY,
)
from codex_plugin_scanner.guard.runtime.extension_control_authority import (
    AuthorityHealth,
    ExtensionControlAuthorityError,
)
from codex_plugin_scanner.guard.runtime.extension_control_contract import (
    ControlState,
    ControlSurface,
)
from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.store_base import (
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


def test_catalog_upgrade_retires_enabled_target_when_matcher_contract_changes(tmp_path: Path) -> None:
    secrets = MemorySecretStore()
    store = _store(tmp_path, secrets)
    store.read_extension_control_authority_for_registry(BUILT_IN_COMMAND_EXTENSION_REGISTRY)
    upgraded_registry, permission_id = _matcher_contract_registry()
    _commit_enabled_permission(store, permission_id, key="enable-before-matcher-contract-change")

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
