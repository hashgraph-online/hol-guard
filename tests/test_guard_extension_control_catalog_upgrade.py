"""Catalog-upgrade persistence for enabled local extension allows."""

from __future__ import annotations

import threading
from pathlib import Path

import pytest

import tests.managed_controls_activation_support as activation_support
from codex_plugin_scanner.guard import store_extension_control_authority as authority_store
from codex_plugin_scanner.guard.managed_controls_policy_bundle import MANAGED_CONTROLS_ACTIVE_STATE_KEY
from codex_plugin_scanner.guard.runtime import command_extensions
from codex_plugin_scanner.guard.runtime.command_extensions import (
    BUILT_IN_COMMAND_EXTENSION_REGISTRY,
    CommandSafetyExtensionRegistry,
)
from codex_plugin_scanner.guard.runtime.extension_control_authority import (
    AuthorityHealth,
    ExtensionControlAuthorityView,
)
from codex_plugin_scanner.guard.runtime.extension_control_contract import (
    ControlState,
    ControlSurface,
    ResolverFailureCode,
)
from codex_plugin_scanner.guard.runtime.extension_control_resolver import resolve_extension_controls
from tests.test_guard_extension_control_authority import (
    MemorySecretStore,
    _commit_enabled_permission,
    _store,
    _upgraded_registry,
)


@pytest.fixture(autouse=True)
def _allow_local_terminal_confirmation(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.runtime.extension_control_proof._require_local_terminal_confirmation",
        lambda _enrollment: None,
    )


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
    assert store.get_sync_payload(MANAGED_CONTROLS_ACTIVE_STATE_KEY) == active


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
