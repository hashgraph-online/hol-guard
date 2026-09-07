from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest

import tests.managed_controls_activation_support as activation_support
from codex_plugin_scanner.guard.approval_gate import ApprovalGateInput, update_settings
from codex_plugin_scanner.guard.managed_controls_policy_bundle import MANAGED_CONTROLS_ACTIVE_STATE_KEY
from codex_plugin_scanner.guard.runtime import command_extensions
from codex_plugin_scanner.guard.runtime.command_extensions import (
    BUILT_IN_COMMAND_EXTENSION_REGISTRY,
    CommandSafetyExtensionRegistry,
)
from codex_plugin_scanner.guard.runtime.extension_control_authority import (
    AuthorityHealth,
    ExtensionControlAuthorityError,
    ExtensionControlAuthorityView,
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
from codex_plugin_scanner.guard.runtime.extension_control_proof import (
    ExtensionControlMutation,
    issue_extension_control_proof,
)
from codex_plugin_scanner.guard.runtime.extension_control_runtime import ExtensionControlRuntime
from codex_plugin_scanner.guard.store import GuardStore

_PASSWORD = "correct horse battery staple"


def _description_only_catalog_variant() -> CommandSafetyExtensionRegistry:
    extensions = BUILT_IN_COMMAND_EXTENSION_REGISTRY.extensions
    return CommandSafetyExtensionRegistry(
        (replace(extensions[0], description=f"{extensions[0].description} Legacy."), *extensions[1:])
    )


def _activate_under_catalog(
    store: GuardStore,
    registry: CommandSafetyExtensionRegistry,
    monkeypatch: pytest.MonkeyPatch,
    *,
    preserve_local_controls: bool = False,
) -> None:
    monkeypatch.setattr(command_extensions, "BUILT_IN_COMMAND_EXTENSION_REGISTRY", registry)
    monkeypatch.setattr(activation_support, "BUILT_IN_COMMAND_EXTENSION_REGISTRY", registry)
    base = store.read_extension_control_authority(catalog_digest=registry.catalog_digest)
    if base.health is AuthorityHealth.UNENROLLED:
        store._bootstrap_extension_control_authority(  # pyright: ignore[reportPrivateUsage]
            registry.catalog_digest,
            key=None,
        )
    if preserve_local_controls:
        _commit_local_control(store, registry)
    assert activation_support.activate_managed_bundle(store, activation_support.managed_bundle()) is True
    monkeypatch.setattr(command_extensions, "BUILT_IN_COMMAND_EXTENSION_REGISTRY", BUILT_IN_COMMAND_EXTENSION_REGISTRY)


def _commit_local_control(store: GuardStore, registry: CommandSafetyExtensionRegistry) -> None:
    update_settings(
        store.guard_home,
        {
            "enabled": True,
            "new_password": _PASSWORD,
            "confirm_password": _PASSWORD,
            "cooldown_seconds": 0,
        },
    )
    extension = registry.extensions[0]
    layer = ExtensionControlLayer(
        schema_version=CONTROL_SCHEMA_VERSION,
        kind=ControlLayerKind.LOCAL_ADMIN,
        catalog_digest=registry.catalog_digest,
        global_lockdown=False,
        controls=(
            ExtensionControl(
                ControlTarget(ControlTargetKind.EXTENSION, extension.extension_id),
                ControlState.DISABLED,
            ),
        ),
    )
    key = "clear-catalog-local-control"
    nonce = f"nonce-{key}"
    mutation = ExtensionControlMutation(
        previous_revision=0,
        catalog_digest=registry.catalog_digest,
        layers=(layer,),
        actor_id="local-admin",
        idempotency_key=key,
        nonce=nonce,
    )
    proof = issue_extension_control_proof(
        store.guard_home,
        mutation,
        approval_gate_input=ApprovalGateInput(password=_PASSWORD),
        session_nonce=f"session-{key}",
    )
    store.commit_extension_control_layers(
        (layer,),
        catalog_digest=registry.catalog_digest,
        actor_id="local-admin",
        expected_revision=0,
        idempotency_key=key,
        nonce=nonce,
        proof=proof,
    )


def test_clear_preserves_persisted_catalog_and_local_controls(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    legacy = _description_only_catalog_variant()
    assert legacy.catalog_digest != BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest
    _activate_under_catalog(store, legacy, monkeypatch, preserve_local_controls=True)
    persisted_before = store.read_persisted_extension_control_authority()
    assert persisted_before.health is AuthorityHealth.PROTECTED
    assert persisted_before.revision == 1
    assert persisted_before.catalog_digest == legacy.catalog_digest
    assert len(persisted_before.layers) == 1
    assert persisted_before.layers[0].kind is ControlLayerKind.LOCAL_ADMIN
    runtime = ExtensionControlRuntime(store.read_extension_control_authority_for_registry(legacy))
    active = store.get_sync_payload(MANAGED_CONTROLS_ACTIVE_STATE_KEY)
    assert isinstance(active, dict)
    assert active["catalogDigest"] == legacy.catalog_digest

    store.clear_policy_bundle_authority(
        "2026-08-23T12:03:00Z",
        policy_bundle_last_error={"reason": "catalog-drift"},
        managed_controls_publish=runtime.publish_after_commit,
    )

    assert store.get_sync_payload(MANAGED_CONTROLS_ACTIVE_STATE_KEY) is None
    assert runtime.current().health is AuthorityHealth.PROTECTED
    assert runtime.current().catalog_digest == legacy.catalog_digest
    assert runtime.current().revision == persisted_before.revision
    assert runtime.current().layers == persisted_before.layers
    assert runtime.current().managed_revision == 2
    persisted_after = store.read_persisted_extension_control_authority()
    assert persisted_after == persisted_before


@pytest.mark.parametrize(
    ("failure", "expected_health"),
    (
        (ExtensionControlAuthorityError("invalid snapshot"), AuthorityHealth.TAMPERED),
        (RuntimeError("authority store unavailable"), AuthorityHealth.DEGRADED_UNACKNOWLEDGED),
    ),
)
def test_persisted_authority_read_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure: Exception,
    expected_health: AuthorityHealth,
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    _activate_under_catalog(store, BUILT_IN_COMMAND_EXTENSION_REGISTRY, monkeypatch)

    def fail_read(_catalog_digest: str) -> ExtensionControlAuthorityView:
        raise failure

    monkeypatch.setattr(store, "_read_extension_control_authority_locked", fail_read)
    view = store.read_persisted_extension_control_authority()

    assert view.health is expected_health
    assert view.catalog_digest == BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest


def test_clear_rejects_active_state_without_its_catalog_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    _activate_under_catalog(store, BUILT_IN_COMMAND_EXTENSION_REGISTRY, monkeypatch)
    with store._connect() as connection:
        row = connection.execute(
            "select payload_json from sync_state where state_key = ?",
            (MANAGED_CONTROLS_ACTIVE_STATE_KEY,),
        ).fetchone()
        assert row is not None
        payload = json.loads(str(row["payload_json"]))
        assert isinstance(payload, dict)
        payload.pop("catalogDigest", None)
        connection.execute(
            "update sync_state set payload_json = ? where state_key = ?",
            (json.dumps(payload, allow_nan=False), MANAGED_CONTROLS_ACTIVE_STATE_KEY),
        )

    with pytest.raises(ExtensionControlAuthorityError, match="invalid managed controls activation"):
        store.clear_policy_bundle_authority(
            "2026-08-23T12:05:00Z",
            policy_bundle_last_error={"reason": "missing-catalog"},
        )


@pytest.mark.parametrize("health", (AuthorityHealth.TAMPERED, AuthorityHealth.DEGRADED_UNACKNOWLEDGED))
def test_clear_publishes_non_protected_authority_and_revokes_remote_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    health: AuthorityHealth,
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    _activate_under_catalog(store, BUILT_IN_COMMAND_EXTENSION_REGISTRY, monkeypatch)
    protected = store.read_extension_control_authority_for_registry(BUILT_IN_COMMAND_EXTENSION_REGISTRY)
    runtime = ExtensionControlRuntime(protected)
    if health is AuthorityHealth.TAMPERED:
        with store._connect() as connection:
            connection.execute(
                "update extension_control_authority_snapshot set snapshot_mac = ? where singleton = 1",
                ("invalid",),
            )
    else:
        degraded = ExtensionControlAuthorityView(
            health,
            protected.revision,
            protected.catalog_digest,
            (),
        )
        monkeypatch.setattr(store, "read_persisted_extension_control_authority", lambda: degraded)

    store.clear_policy_bundle_authority(
        "2026-08-23T12:04:00Z",
        policy_bundle_last_error={"reason": health.value},
        managed_controls_publish=runtime.publish_after_commit,
    )

    assert store.get_sync_payload(MANAGED_CONTROLS_ACTIVE_STATE_KEY) is None
    assert runtime.current().health is health
    assert runtime.current().layers == ()
    assert runtime.current().catalog_digest == protected.catalog_digest
    assert runtime.current().managed_revision == 2
