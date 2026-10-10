"""Opt-in Google Workspace CLI rules activate only under local authority.

A signed Cloud layer may turn these rule sets off but never on. A local enable
does not survive a changed rule contract, and revoking it cannot be undone by
replaying the earlier grant.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.runtime.extension_control_authority import (
    AuthorityHealth,
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
from codex_plugin_scanner.guard.runtime.extension_trust import activation_for, extension_is_active, trust_class_for
from codex_plugin_scanner.guard.store import GuardStore
from tests.guard_extension_control_authority_fixtures import MemorySecretStore, _proof, _store

WORKSPACE_CLI_EXTENSIONS = ("command.google-workspace.gws", "command.google-workspace.gog")


@pytest.fixture(autouse=True)
def _allow_local_terminal_confirmation(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.runtime.extension_control_proof._require_local_terminal_confirmation",
        lambda _enrollment: None,
    )


def _layer(kind: ControlLayerKind, extension_id: str, state: ControlState) -> ExtensionControlLayer:
    return ExtensionControlLayer(
        schema_version=CONTROL_SCHEMA_VERSION,
        kind=kind,
        catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
        global_lockdown=False,
        controls=(ExtensionControl(ControlTarget(ControlTargetKind.EXTENSION, extension_id), state),),
    )


def _commit_local(store: GuardStore, extension_id: str, state: ControlState, *, revision: int, key: str) -> None:
    layers = (_layer(ControlLayerKind.LOCAL_ADMIN, extension_id, state),)
    nonce = f"nonce-{key}"
    store.commit_extension_control_layers(
        layers,
        catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
        actor_id="local-admin",
        expected_revision=revision,
        idempotency_key=key,
        nonce=nonce,
        proof=_proof(store, layers, revision=revision, key=key, actor_id="local-admin", nonce=nonce),
    )


def _authority_layers(store: GuardStore) -> tuple[ExtensionControlLayer, ...]:
    view = store.read_extension_control_authority_for_registry(BUILT_IN_COMMAND_EXTENSION_REGISTRY)
    assert view.health is AuthorityHealth.PROTECTED
    return view.layers


@pytest.mark.parametrize("extension_id", WORKSPACE_CLI_EXTENSIONS)
def test_workspace_cli_rules_are_external_and_opt_in(extension_id: str) -> None:
    assert trust_class_for(extension_id) == "external"
    assert activation_for(extension_id) == "opt-in"
    assert extension_is_active(extension_id, ()) is False


@pytest.mark.parametrize("extension_id", WORKSPACE_CLI_EXTENSIONS)
def test_signed_cloud_enable_cannot_activate_workspace_cli_rules(extension_id: str) -> None:
    cloud_enable = _layer(ControlLayerKind.SIGNED_CLOUD, extension_id, ControlState.ENABLED)

    assert extension_is_active(extension_id, (cloud_enable,)) is False


@pytest.mark.parametrize("extension_id", WORKSPACE_CLI_EXTENSIONS)
def test_local_admin_enable_activates_and_cloud_disable_still_wins(extension_id: str) -> None:
    local_enable = _layer(ControlLayerKind.LOCAL_ADMIN, extension_id, ControlState.ENABLED)
    cloud_disable = _layer(ControlLayerKind.SIGNED_CLOUD, extension_id, ControlState.DISABLED)

    assert extension_is_active(extension_id, (local_enable,)) is True
    assert extension_is_active(extension_id, (local_enable, cloud_disable)) is False


@pytest.mark.parametrize("extension_id", WORKSPACE_CLI_EXTENSIONS)
def test_changed_rule_contract_retires_local_enable(tmp_path: Path, extension_id: str) -> None:
    store = _store(tmp_path, MemorySecretStore())
    _ = _authority_layers(store)
    _commit_local(store, extension_id, ControlState.ENABLED, revision=0, key="enable")
    assert extension_is_active(extension_id, _authority_layers(store)) is True

    original = store._catalog_target_manifest

    @staticmethod
    def changed_contract(registry):
        manifest = dict(original(registry))
        target = f"extension:{extension_id}"
        assert target in manifest
        manifest[target] = "0" * 64
        return manifest

    store._catalog_target_manifest = changed_contract

    assert extension_is_active(extension_id, _authority_layers(store)) is False


@pytest.mark.parametrize("extension_id", WORKSPACE_CLI_EXTENSIONS)
def test_replaying_earlier_grant_cannot_undo_revocation(tmp_path: Path, extension_id: str) -> None:
    store = _store(tmp_path, MemorySecretStore())
    _ = _authority_layers(store)
    _commit_local(store, extension_id, ControlState.ENABLED, revision=0, key="enable")
    _commit_local(store, extension_id, ControlState.DISABLED, revision=1, key="revoke")
    assert extension_is_active(extension_id, _authority_layers(store)) is False

    with pytest.raises(ExtensionControlAuthorityError, match="revision mismatch"):
        _commit_local(store, extension_id, ControlState.ENABLED, revision=0, key="enable")
    with pytest.raises(ExtensionControlAuthorityError, match="revision conflict"):
        _commit_local(store, extension_id, ControlState.ENABLED, revision=0, key="enable-again")

    assert extension_is_active(extension_id, _authority_layers(store)) is False
