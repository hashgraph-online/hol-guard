"""Committed policy events and authenticated history."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.extension_control_events import extension_control_change_payload
from codex_plugin_scanner.guard.runtime.command_extensions import (
    BUILT_IN_COMMAND_EXTENSION_REGISTRY,
)
from codex_plugin_scanner.guard.runtime.extension_control_authority import (
    ExtensionControlAuthorityError,
)
from codex_plugin_scanner.guard.runtime.extension_control_contract import (
    CONTROL_SCHEMA_VERSION,
    ControlLayerKind,
    ControlState,
    ControlTarget,
    ControlTargetKind,
    ExtensionControl,
    ExtensionControlLayer,
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
