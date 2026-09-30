"""Catalog-upgrade persistence for enabled local extension allows."""

from __future__ import annotations

import threading
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path

import pytest

import tests.managed_controls_activation_support as activation_support
from codex_plugin_scanner.guard import store_extension_control_authority as authority_store
from codex_plugin_scanner.guard.managed_controls_policy_bundle import (
    MANAGED_CONTROLS_ACTIVATION_PURPOSE,
    MANAGED_CONTROLS_ACTIVE_STATE_KEY,
    _projection_digest,
)
from codex_plugin_scanner.guard.runtime import command_extensions
from codex_plugin_scanner.guard.runtime.command_extensions import (
    BUILT_IN_COMMAND_EXTENSION_REGISTRY,
    CommandSafetyExtensionRegistry,
)
from codex_plugin_scanner.guard.runtime.extension_control_authority import (
    AuthorityHealth,
    ExtensionControlAuthorityError,
    ExtensionControlAuthorityView,
    authenticated_record,
    layers_from_json,
    layers_to_json,
)
from codex_plugin_scanner.guard.runtime.extension_control_contract import (
    ControlLayerKind,
    ControlState,
    ControlSurface,
    ControlTarget,
    ControlTargetKind,
    ResolverFailureCode,
)
from codex_plugin_scanner.guard.runtime.extension_control_resolver import resolve_extension_controls
from tests.test_guard_extension_control_authority import (
    MemorySecretStore,
    _commit_enabled_permission,
    _expanded_permission_registry,
    _store,
    _upgraded_registry,
)


@pytest.fixture(autouse=True)
def _allow_local_terminal_confirmation(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.runtime.extension_control_proof._require_local_terminal_confirmation",
        lambda _enrollment: None,
    )


def _replace_active_managed_control(
    store: authority_store.GuardStore,
    *,
    target_kind: ControlTargetKind,
    target_id: str,
) -> None:
    active = store.get_sync_payload(MANAGED_CONTROLS_ACTIVE_STATE_KEY)
    assert isinstance(active, dict)
    encoded_layers = active.get("signedCloudLayersJson")
    assert isinstance(encoded_layers, str)
    layers = layers_from_json(encoded_layers)
    assert len(layers) == 1
    control = replace(
        layers[0].controls[0],
        target=ControlTarget(target_kind, target_id),
        state=ControlState.ENABLED,
    )
    unsigned = dict(active)
    unsigned.pop("authentication", None)
    unsigned["signedCloudLayersJson"] = layers_to_json((replace(layers[0], controls=(control,)),))
    acknowledgement = unsigned.get("acknowledgement")
    assert isinstance(acknowledgement, dict)
    unsigned["acknowledgement"] = {
        **acknowledgement,
        "effectiveProjectionDigest": _projection_digest(unsigned),
    }
    key = store._authority_key(required=True)  # pyright: ignore[reportPrivateUsage]
    assert key is not None
    record, digest, mac = authenticated_record(
        {"activation": unsigned},
        key=key,
        purpose=MANAGED_CONTROLS_ACTIVATION_PURPOSE,
    )
    unsigned["authentication"] = {"record": record, "digest": digest, "mac": mac}
    store.set_sync_payload(MANAGED_CONTROLS_ACTIVE_STATE_KEY, unsigned, "2026-08-23T12:02:00Z")


def _changed_extension_registry() -> tuple[CommandSafetyExtensionRegistry, str]:
    extensions = BUILT_IN_COMMAND_EXTENSION_REGISTRY.extensions
    changed = replace(extensions[0], project_markers=(*extensions[0].project_markers, "changed-marker"))
    return CommandSafetyExtensionRegistry((changed, *extensions[1:])), changed.extension_id


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


def test_catalog_upgrade_projects_active_managed_controls_without_rewriting_ack(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secrets = MemorySecretStore()
    store = _store(tmp_path, secrets, enroll=False)
    legacy = _upgraded_registry()
    monkeypatch.setattr(command_extensions, "BUILT_IN_COMMAND_EXTENSION_REGISTRY", legacy)
    monkeypatch.setattr(activation_support, "BUILT_IN_COMMAND_EXTENSION_REGISTRY", legacy)
    store._bootstrap_extension_control_authority(legacy.catalog_digest, key=None)  # pyright: ignore[reportPrivateUsage]

    assert activation_support.activate_managed_bundle(store, activation_support.managed_bundle()) is True
    active = store.get_sync_payload(MANAGED_CONTROLS_ACTIVE_STATE_KEY)
    assert isinstance(active, dict)
    assert active["catalogDigest"] == legacy.catalog_digest
    persisted = store.read_persisted_extension_control_authority()
    assert persisted.health is AuthorityHealth.PROTECTED
    assert persisted.catalog_digest == legacy.catalog_digest

    monkeypatch.setattr(command_extensions, "BUILT_IN_COMMAND_EXTENSION_REGISTRY", BUILT_IN_COMMAND_EXTENSION_REGISTRY)
    monkeypatch.setattr(activation_support, "BUILT_IN_COMMAND_EXTENSION_REGISTRY", BUILT_IN_COMMAND_EXTENSION_REGISTRY)

    upgraded = store.read_extension_control_authority_for_registry(BUILT_IN_COMMAND_EXTENSION_REGISTRY)

    assert upgraded.health is AuthorityHealth.PROTECTED
    assert upgraded.catalog_digest == BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest
    assert upgraded.managed_revision == 1
    managed_layer = next(layer for layer in upgraded.layers if layer.kind is ControlLayerKind.SIGNED_CLOUD)
    assert managed_layer.controls[0].state is ControlState.DISABLED
    assert store.get_sync_payload(MANAGED_CONTROLS_ACTIVE_STATE_KEY) == active


def test_catalog_upgrade_fails_closed_when_managed_manifest_is_missing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secrets = MemorySecretStore()
    store = _store(tmp_path, secrets, enroll=False)
    legacy = _upgraded_registry()
    monkeypatch.setattr(command_extensions, "BUILT_IN_COMMAND_EXTENSION_REGISTRY", legacy)
    monkeypatch.setattr(activation_support, "BUILT_IN_COMMAND_EXTENSION_REGISTRY", legacy)
    store._bootstrap_extension_control_authority(legacy.catalog_digest, key=None)  # pyright: ignore[reportPrivateUsage]
    assert activation_support.activate_managed_bundle(store, activation_support.managed_bundle()) is True

    permission_id = BUILT_IN_COMMAND_EXTENSION_REGISTRY.extensions[0].permissions[0].permission_id
    _replace_active_managed_control(
        store,
        target_kind=ControlTargetKind.PERMISSION,
        target_id=permission_id,
    )
    active_before_projection = store.get_sync_payload(MANAGED_CONTROLS_ACTIVE_STATE_KEY)
    with store._connect() as connection:
        connection.execute("delete from extension_control_catalog_manifest")

    monkeypatch.setattr(command_extensions, "BUILT_IN_COMMAND_EXTENSION_REGISTRY", BUILT_IN_COMMAND_EXTENSION_REGISTRY)
    monkeypatch.setattr(activation_support, "BUILT_IN_COMMAND_EXTENSION_REGISTRY", BUILT_IN_COMMAND_EXTENSION_REGISTRY)
    upgraded = store.read_extension_control_authority_for_registry(BUILT_IN_COMMAND_EXTENSION_REGISTRY)

    assert upgraded.health is AuthorityHealth.PROTECTED
    managed_layer = next(layer for layer in upgraded.layers if layer.kind is ControlLayerKind.SIGNED_CLOUD)
    assert managed_layer.controls[0].target.target_id == permission_id
    assert managed_layer.controls[0].state is ControlState.DISABLED
    assert store.get_sync_payload(MANAGED_CONTROLS_ACTIVE_STATE_KEY) == active_before_projection
    resolution = resolve_extension_controls(
        upgraded.layers,
        BUILT_IN_COMMAND_EXTENSION_REGISTRY,
        extension_ids=(),
        permission_ids=(permission_id,),
        surface=ControlSurface.COMMAND_EVALUATION,
    )
    assert resolution.blocked is True


@pytest.mark.parametrize(
    ("registry_factory", "target_kind"),
    (
        (_expanded_permission_registry, ControlTargetKind.PERMISSION),
        (_changed_extension_registry, ControlTargetKind.EXTENSION),
    ),
    ids=("permission-contract", "extension-contract"),
)
def test_catalog_upgrade_disables_managed_allow_when_target_contract_changes(
    tmp_path: Path,
    registry_factory: Callable[[], tuple[CommandSafetyExtensionRegistry, str]],
    target_kind: ControlTargetKind,
) -> None:
    secrets = MemorySecretStore()
    store = _store(tmp_path, secrets, enroll=False)
    assert activation_support.activate_managed_bundle(store, activation_support.managed_bundle()) is True
    assert store.read_extension_control_authority_for_registry(BUILT_IN_COMMAND_EXTENSION_REGISTRY).health is (
        AuthorityHealth.PROTECTED
    )
    changed_registry, target_id = registry_factory()
    _replace_active_managed_control(store, target_kind=target_kind, target_id=target_id)
    active_before_projection = store.get_sync_payload(MANAGED_CONTROLS_ACTIVE_STATE_KEY)

    upgraded = store.read_extension_control_authority_for_registry(changed_registry)

    assert upgraded.health is AuthorityHealth.PROTECTED
    managed_layer = next(layer for layer in upgraded.layers if layer.kind is ControlLayerKind.SIGNED_CLOUD)
    assert managed_layer.controls[0].state is ControlState.DISABLED
    assert store.get_sync_payload(MANAGED_CONTROLS_ACTIVE_STATE_KEY) == active_before_projection
    resolution = resolve_extension_controls(
        upgraded.layers,
        changed_registry,
        extension_ids=(target_id,) if target_kind is ControlTargetKind.EXTENSION else (),
        permission_ids=(target_id,) if target_kind is ControlTargetKind.PERMISSION else (),
        surface=ControlSurface.COMMAND_EVALUATION,
    )
    assert resolution.blocked is True


def test_managed_projection_requires_current_manifest_for_catalog_rebind(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secrets = MemorySecretStore()
    store = _store(tmp_path, secrets, enroll=False)
    legacy = _upgraded_registry()
    monkeypatch.setattr(command_extensions, "BUILT_IN_COMMAND_EXTENSION_REGISTRY", legacy)
    monkeypatch.setattr(activation_support, "BUILT_IN_COMMAND_EXTENSION_REGISTRY", legacy)
    store._bootstrap_extension_control_authority(legacy.catalog_digest, key=None)  # pyright: ignore[reportPrivateUsage]
    assert activation_support.activate_managed_bundle(store, activation_support.managed_bundle()) is True

    monkeypatch.setattr(command_extensions, "BUILT_IN_COMMAND_EXTENSION_REGISTRY", BUILT_IN_COMMAND_EXTENSION_REGISTRY)
    monkeypatch.setattr(activation_support, "BUILT_IN_COMMAND_EXTENSION_REGISTRY", BUILT_IN_COMMAND_EXTENSION_REGISTRY)
    view = store.read_extension_control_authority_for_registry(
        BUILT_IN_COMMAND_EXTENSION_REGISTRY,
        include_managed_controls=False,
    )

    with pytest.raises(ExtensionControlAuthorityError, match="current catalog manifest is missing"):
        store._with_managed_controls_activation(view)  # pyright: ignore[reportPrivateUsage]


def test_catalog_upgrade_does_not_overwrite_replaced_managed_controls(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secrets = MemorySecretStore()
    store = _store(tmp_path, secrets, enroll=False)
    legacy = _upgraded_registry()
    monkeypatch.setattr(command_extensions, "BUILT_IN_COMMAND_EXTENSION_REGISTRY", legacy)
    monkeypatch.setattr(activation_support, "BUILT_IN_COMMAND_EXTENSION_REGISTRY", legacy)
    store._bootstrap_extension_control_authority(legacy.catalog_digest, key=None)  # pyright: ignore[reportPrivateUsage]
    assert activation_support.activate_managed_bundle(store, activation_support.managed_bundle()) is True

    monkeypatch.setattr(command_extensions, "BUILT_IN_COMMAND_EXTENSION_REGISTRY", BUILT_IN_COMMAND_EXTENSION_REGISTRY)
    monkeypatch.setattr(activation_support, "BUILT_IN_COMMAND_EXTENSION_REGISTRY", BUILT_IN_COMMAND_EXTENSION_REGISTRY)

    entered = threading.Event()
    release = threading.Event()
    original_loader = authority_store.managed_controls_layers_from_activation_state

    def blocked_loader(*args: object, **kwargs: object) -> tuple[tuple[object, ...], int]:
        entered.set()
        assert release.wait(timeout=5)
        return original_loader(*args, **kwargs)

    monkeypatch.setattr(authority_store, "managed_controls_layers_from_activation_state", blocked_loader)
    read_results: list[ExtensionControlAuthorityView] = []
    reader = threading.Thread(
        target=lambda: read_results.append(
            store.read_extension_control_authority_for_registry(BUILT_IN_COMMAND_EXTENSION_REGISTRY)
        ),
        daemon=True,
    )
    reader.start()
    try:
        assert entered.wait(timeout=5)
        store.set_sync_payload(MANAGED_CONTROLS_ACTIVE_STATE_KEY, {}, "2026-08-23T12:01:00Z")
    finally:
        release.set()
    reader.join(timeout=5)

    assert not reader.is_alive()
    assert len(read_results) == 1
    assert read_results[0].health is AuthorityHealth.PROTECTED
    assert read_results[0].managed_revision == 1
    assert store.get_sync_payload(MANAGED_CONTROLS_ACTIVE_STATE_KEY) == {}


def test_catalog_upgrade_rejects_tampered_old_managed_activation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secrets = MemorySecretStore()
    store = _store(tmp_path, secrets, enroll=False)
    legacy = _upgraded_registry()
    monkeypatch.setattr(command_extensions, "BUILT_IN_COMMAND_EXTENSION_REGISTRY", legacy)
    monkeypatch.setattr(activation_support, "BUILT_IN_COMMAND_EXTENSION_REGISTRY", legacy)
    store._bootstrap_extension_control_authority(legacy.catalog_digest, key=None)  # pyright: ignore[reportPrivateUsage]
    assert activation_support.activate_managed_bundle(store, activation_support.managed_bundle()) is True
    active = store.get_sync_payload(MANAGED_CONTROLS_ACTIVE_STATE_KEY)
    assert isinstance(active, dict)
    authentication = active.get("authentication")
    assert isinstance(authentication, dict)
    authentication["mac"] = "tampered"
    store.set_sync_payload(MANAGED_CONTROLS_ACTIVE_STATE_KEY, active, "2026-08-23T12:01:00Z")

    monkeypatch.setattr(command_extensions, "BUILT_IN_COMMAND_EXTENSION_REGISTRY", BUILT_IN_COMMAND_EXTENSION_REGISTRY)
    monkeypatch.setattr(activation_support, "BUILT_IN_COMMAND_EXTENSION_REGISTRY", BUILT_IN_COMMAND_EXTENSION_REGISTRY)
    upgraded = store.read_extension_control_authority_for_registry(BUILT_IN_COMMAND_EXTENSION_REGISTRY)

    assert upgraded.health is AuthorityHealth.TAMPERED
    assert store.get_sync_payload(MANAGED_CONTROLS_ACTIVE_STATE_KEY) == active


def test_catalog_upgrade_keeps_removed_managed_targets_fail_closed(
    tmp_path: Path,
) -> None:
    secrets = MemorySecretStore()
    store = _store(tmp_path, secrets, enroll=False)
    store._bootstrap_extension_control_authority(  # pyright: ignore[reportPrivateUsage]
        BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
        key=None,
    )
    assert activation_support.activate_managed_bundle(store, activation_support.managed_bundle()) is True
    removed_registry = CommandSafetyExtensionRegistry(
        tuple(
            extension
            for extension in BUILT_IN_COMMAND_EXTENSION_REGISTRY.extensions
            if extension.extension_id != "command.git"
        )
    )

    upgraded = store.read_extension_control_authority_for_registry(removed_registry)
    resolution = resolve_extension_controls(
        upgraded.layers,
        removed_registry,
        extension_ids=(),
        permission_ids=(),
        surface=ControlSurface.COMMAND_EVALUATION,
    )

    assert upgraded.health is AuthorityHealth.PROTECTED
    assert resolution.blocked is True
    assert ResolverFailureCode.UNKNOWN_PERMISSION_TARGET in {failure.code for failure in resolution.failures}
