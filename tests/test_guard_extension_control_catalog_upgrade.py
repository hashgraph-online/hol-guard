"""Catalog-upgrade persistence for enabled local extension allows."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.runtime.extension_control_authority import AuthorityHealth
from codex_plugin_scanner.guard.runtime.extension_control_contract import ControlState
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
