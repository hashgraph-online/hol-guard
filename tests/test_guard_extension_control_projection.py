from __future__ import annotations

from codex_plugin_scanner.guard.daemon.extension_control_projection import (
    EFFECTIVE_PROJECTION_SCHEMA,
    build_effective_extension_control_projection,
)
from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.runtime.extension_control_authority import AuthorityHealth, ExtensionControlAuthorityView
from codex_plugin_scanner.guard.runtime.extension_control_contract import (
    CONTROL_SCHEMA_VERSION,
    ControlLayerKind,
    ControlState,
    ControlTarget,
    ControlTargetKind,
    ExtensionControl,
    ExtensionControlLayer,
)
from codex_plugin_scanner.guard.runtime.extension_control_runtime import ExtensionControlRuntimeSnapshot


def _snapshot(*layers: ExtensionControlLayer, health: AuthorityHealth = AuthorityHealth.PROTECTED) -> ExtensionControlRuntimeSnapshot:
    return ExtensionControlRuntimeSnapshot.from_authority_view(
        ExtensionControlAuthorityView(
            health,
            7,
            BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
            layers,
        )
    )


def _layer(kind: ControlLayerKind, *controls: ExtensionControl, lockdown: bool = False) -> ExtensionControlLayer:
    return ExtensionControlLayer(
        CONTROL_SCHEMA_VERSION,
        kind,
        BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
        lockdown,
        controls,
    )


def test_projection_matches_resolver_and_explains_local_and_managed_state() -> None:
    permission = next(item for item in BUILT_IN_COMMAND_EXTENSION_REGISTRY.permissions if item.configurable)
    local = _layer(
        ControlLayerKind.LOCAL_ADMIN,
        ExtensionControl(ControlTarget(ControlTargetKind.PERMISSION, permission.permission_id), ControlState.ENABLED),
    )
    managed = _layer(
        ControlLayerKind.SIGNED_CLOUD,
        ExtensionControl(ControlTarget(ControlTargetKind.PERMISSION, permission.permission_id), ControlState.DISABLED),
    )
    projection = build_effective_extension_control_projection(
        BUILT_IN_COMMAND_EXTENSION_REGISTRY,
        _snapshot(local, managed),
    )

    assert projection["schema_version"] == EFFECTIVE_PROJECTION_SCHEMA
    assert projection["revision"] == 7
    permission_items = {item["permission_id"]: item for item in projection["permissions"]}
    item = permission_items[permission.permission_id]
    assert item["local_state"] == "enabled"
    assert item["managed_state"] == "disabled"
    assert item["effective_state"] == "blocked"
    assert "control.disabled-permission" in item["reason_codes"]


def test_projection_fails_closed_for_unavailable_authority_and_lockdown() -> None:
    projection = build_effective_extension_control_projection(
        BUILT_IN_COMMAND_EXTENSION_REGISTRY,
        _snapshot(health=AuthorityHealth.DEGRADED_UNACKNOWLEDGED),
    )
    assert projection["extensions"]
    assert all(item["effective_state"] == "blocked" for item in projection["extensions"])
    assert all(item["effective_state"] == "blocked" for item in projection["permissions"])
    assert all("control.resolver-failure" in item["reason_codes"] for item in projection["permissions"])

    lockdown = _layer(ControlLayerKind.LOCAL_ADMIN, lockdown=True)
    projection = build_effective_extension_control_projection(
        BUILT_IN_COMMAND_EXTENSION_REGISTRY,
        _snapshot(lockdown),
    )
    assert all(item["effective_state"] == "blocked" for item in projection["extensions"])
    assert all("control.global-lockdown" in item["reason_codes"] for item in projection["permissions"])


def test_projection_order_and_cardinality_are_deterministic() -> None:
    projection = build_effective_extension_control_projection(
        BUILT_IN_COMMAND_EXTENSION_REGISTRY,
        _snapshot(),
    )
    extension_ids = [item["extension_id"] for item in projection["extensions"]]
    permission_ids = [item["permission_id"] for item in projection["permissions"]]
    assert extension_ids == sorted(extension_ids)
    assert permission_ids == sorted(permission_ids)
    assert len(extension_ids) == len(BUILT_IN_COMMAND_EXTENSION_REGISTRY.extensions)
    assert len(permission_ids) == len(BUILT_IN_COMMAND_EXTENSION_REGISTRY.permissions)
