from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import store_policy_integrity_backend as policy_integrity_backend_module
from codex_plugin_scanner.guard.native_command_control_authority import AUTHORITY_FILE_NAME, encode_authority
from codex_plugin_scanner.guard.native_command_control_authority_io import write_private_state
from codex_plugin_scanner.guard.native_command_control_authority_store import _key as native_authority_key
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


@pytest.mark.parametrize("catalog_changed", (False, True))
def test_authenticated_recovery_preserves_committed_controls_without_self_locking(
    tmp_path: Path, catalog_changed: bool
) -> None:
    store = _store(tmp_path, MemorySecretStore())
    _commit(store)
    before = store.read_extension_control_authority_for_registry(BUILT_IN_COMMAND_EXTENSION_REGISTRY)
    registry = _upgraded_registry() if catalog_changed else BUILT_IN_COMMAND_EXTENSION_REGISTRY

    recovered = store.recover_extension_control_authority(
        catalog_digest=registry.catalog_digest,
        migration_registry=registry,
    )

    assert recovered.health is AuthorityHealth.PROTECTED
    assert recovered.revision == before.revision + int(catalog_changed)
    assert recovered.catalog_digest == registry.catalog_digest
    assert recovered.layers[0].controls == before.layers[0].controls


def test_failed_recovery_verification_does_not_queue_policy_change(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = _store(tmp_path, MemorySecretStore())
    _commit(store)
    with store._connect() as connection:
        connection.execute("delete from guard_cloud_events where event_type = 'policy.changed'")
        connection.commit()

    def failed_read(*_args: object, **_kwargs: object) -> None:
        raise ExtensionControlAuthorityError("injected verification failure")

    monkeypatch.setattr(store, "_read_extension_control_authority_locked", failed_read)
    with pytest.raises(ExtensionControlAuthorityError, match="injected verification failure"):
        store.recover_extension_control_authority(catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest)
    with store._connect() as connection:
        count = connection.execute(
            "select count(*) from guard_cloud_events where event_type = 'policy.changed'"
        ).fetchone()[0]
    assert count == 0


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


def test_linux_enrollment_uses_daemon_native_authority_after_keyring_session_changes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    keyring_values: dict[str, str] = {}
    monkeypatch.setattr(policy_integrity_backend_module.sys, "platform", "linux", raising=False)
    monkeypatch.setattr(SystemKeyringSecretStore, "_backend_is_available", classmethod(lambda cls: True))
    monkeypatch.setattr(SystemKeyringSecretStore, "get_secret", lambda self, secret_id: keyring_values.get(secret_id))
    monkeypatch.setattr(
        SystemKeyringSecretStore,
        "set_secret",
        lambda self, secret_id, value: keyring_values.__setitem__(secret_id, value),
    )
    secrets = MemorySecretStore()
    daemon_store = _store(tmp_path, secrets, enroll=False)
    marker = {
        "schema": "guard.native-command-control-authority.v1",
        "epoch": 1,
        "mutation_revision": 1,
        "authority_key_id": "0" * 64,
        "phase": "closed",
        "effective_digest": None,
        "recovery": None,
    }
    write_private_state(
        tmp_path, AUTHORITY_FILE_NAME, encode_authority(marker, native_authority_key(daemon_store)), 4096
    )

    monkeypatch.setattr(SystemKeyringSecretStore, "_backend_is_available", classmethod(lambda cls: False))
    terminal_store = GuardStore(tmp_path, prime_policy_integrity=False)
    terminal_store._extension_control_authority_secret_store = secrets

    assert _enroll(terminal_store).health is AuthorityHealth.PROTECTED


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
    store.read_extension_control_authority_for_registry(BUILT_IN_COMMAND_EXTENSION_REGISTRY)
    _commit(store)
    with store._connect() as connection:
        legacy_manifest = connection.execute(
            "select * from extension_control_catalog_manifest where catalog_digest = ?",
            (original_digest,),
        ).fetchone()
    assert legacy_manifest is not None
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
        persisted_legacy_manifest = connection.execute(
            "select * from extension_control_catalog_manifest where catalog_digest = ?",
            (original_digest,),
        ).fetchone()
        persisted_upgraded_manifest = connection.execute(
            "select * from extension_control_catalog_manifest where catalog_digest = ?",
            (upgraded_digest,),
        ).fetchone()
    assert dict(persisted_legacy_manifest) == dict(legacy_manifest)
    assert persisted_upgraded_manifest is not None
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
