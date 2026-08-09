from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.daemon.extension_control_api import ExtensionControlApiError, ExtensionControlApiService
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
from codex_plugin_scanner.guard.runtime.extension_control_runtime import ExtensionControlRuntime
from codex_plugin_scanner.guard.store import GuardStore


def _configurable_permission():
    return next(permission for permission in BUILT_IN_COMMAND_EXTENSION_REGISTRY.permissions if permission.configurable)


def _fixed_permission():
    return next(permission for permission in BUILT_IN_COMMAND_EXTENSION_REGISTRY.permissions if not permission.configurable)


def _layer(*controls: ExtensionControl, kind: ControlLayerKind = ControlLayerKind.LOCAL_ADMIN) -> ExtensionControlLayer:
    return ExtensionControlLayer(
        CONTROL_SCHEMA_VERSION,
        kind,
        BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
        False,
        controls,
    )


def _service(tmp_path: Path, *, layers: tuple[ExtensionControlLayer, ...] = ()) -> ExtensionControlApiService:
    view = ExtensionControlAuthorityView(
        AuthorityHealth.PROTECTED,
        4,
        BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
        layers,
    )
    return ExtensionControlApiService(
        store=GuardStore(tmp_path / "guard-home"),
        registry=BUILT_IN_COMMAND_EXTENSION_REGISTRY,
        runtime=ExtensionControlRuntime(view),
    )


def _payload(layers: tuple[ExtensionControlLayer, ...]) -> dict[str, object]:
    return {
        "previous_revision": 4,
        "catalog_digest": BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
        "layers": [
            {
                "schema_version": layer.schema_version,
                "kind": layer.kind.value,
                "catalog_digest": layer.catalog_digest,
                "global_lockdown": layer.global_lockdown,
                "controls": [
                    {
                        "target_kind": control.target.kind.value,
                        "target_id": control.target.target_id,
                        "state": control.state.value,
                    }
                    for control in layer.controls
                ],
            }
            for layer in layers
        ],
        "actor_id": "dashboard-admin",
        "idempotency_key": "semantic-preview-1",
        "nonce": "semantic-preview-nonce",
    }


def test_permission_preview_reports_effective_blast_radius_without_rewriting_baseline(tmp_path: Path) -> None:
    permission = _configurable_permission()
    control = ExtensionControl(ControlTarget(ControlTargetKind.PERMISSION, permission.permission_id), ControlState.DISABLED)
    preview = _service(tmp_path).preview(_payload((_layer(control),)))

    semantic = preview["semantic_preview"]
    assert semantic["changed_target_count"] == 1
    assert semantic["approval_required"] is True
    target = semantic["changed_targets"][0]
    assert target["target"] == {"kind": "permission", "target_id": permission.permission_id}
    assert target["before_explicit"] == "inherited"
    assert target["after_explicit"] == "disabled"
    assert target["after_effective"] == "blocked"
    assert target["baseline_risk"] == permission.risk_tier
    assert target["baseline_floor"] == permission.baseline_floor
    assert target["dependency_permission_ids"] == sorted(permission.dependencies)
    assert target["implied_permission_ids"] == sorted(permission.implied_permissions)
    assert target["conflict_permission_ids"] == sorted(permission.conflicts)
    assert permission.extension_id in target["affected_extension_ids"]
    assert set(permission.rule_ids).issubset(set(target["affected_rule_ids"]))
    assert target["provenance"] == ["local-admin"]
    assert preview.get("proof_id") is None


def test_preview_explains_when_managed_disable_dominates_local_allow(tmp_path: Path) -> None:
    permission = _configurable_permission()
    managed_control = ExtensionControl(ControlTarget(ControlTargetKind.PERMISSION, permission.permission_id), ControlState.DISABLED)
    managed = _layer(managed_control, kind=ControlLayerKind.SIGNED_CLOUD)
    local_allow = ExtensionControl(ControlTarget(ControlTargetKind.PERMISSION, permission.permission_id), ControlState.ENABLED)
    preview = _service(tmp_path, layers=(managed,)).preview(_payload((_layer(local_allow), managed)))

    target = preview["semantic_preview"]["changed_targets"][0]
    assert target["after_explicit"] == "enabled"
    assert target["after_effective"] == "blocked"
    assert target["provenance"] == ["local-admin", "signed-cloud"]
    assert any(warning["code"] == "requested-allow-not-effective" for warning in target["warnings"])


def test_client_cannot_mutate_or_remove_signed_cloud_layer(tmp_path: Path) -> None:
    permission = _configurable_permission()
    managed = _layer(
        ExtensionControl(ControlTarget(ControlTargetKind.PERMISSION, permission.permission_id), ControlState.DISABLED),
        kind=ControlLayerKind.SIGNED_CLOUD,
    )
    service = _service(tmp_path, layers=(managed,))
    with pytest.raises(ExtensionControlApiError) as removed:
        service.preview(_payload(()))
    assert (removed.value.status, removed.value.code) == (403, "managed_layer_mutation")

    changed = _layer(
        ExtensionControl(ControlTarget(ControlTargetKind.PERMISSION, permission.permission_id), ControlState.ENABLED),
        kind=ControlLayerKind.SIGNED_CLOUD,
    )
    with pytest.raises(ExtensionControlApiError) as mutated:
        service.preview(_payload((changed,)))
    assert (mutated.value.status, mutated.value.code) == (403, "managed_layer_mutation")


def test_local_draft_cannot_create_fixed_permission_or_required_extension_controls(tmp_path: Path) -> None:
    fixed = _fixed_permission()
    fixed_control = ExtensionControl(ControlTarget(ControlTargetKind.PERMISSION, fixed.permission_id), ControlState.DISABLED)
    service = _service(tmp_path)
    with pytest.raises(ExtensionControlApiError) as fixed_error:
        service.preview(_payload((_layer(fixed_control),)))
    assert (fixed_error.value.status, fixed_error.value.code) == (403, "immutable_permission")

    required = next(extension for extension in BUILT_IN_COMMAND_EXTENSION_REGISTRY.extensions if extension.required)
    required_control = ExtensionControl(ControlTarget(ControlTargetKind.EXTENSION, required.extension_id), ControlState.DISABLED)
    with pytest.raises(ExtensionControlApiError) as extension_error:
        service.preview(_payload((_layer(required_control),)))
    assert (extension_error.value.status, extension_error.value.code) == (403, "immutable_extension")


def test_legacy_immutable_control_can_be_preserved_or_removed_but_not_changed(tmp_path: Path) -> None:
    fixed = _fixed_permission()
    legacy = ExtensionControl(ControlTarget(ControlTargetKind.PERMISSION, fixed.permission_id), ControlState.DISABLED)
    current = _layer(legacy)
    service = _service(tmp_path, layers=(current,))

    preserved = service.preview(_payload((current,)))
    assert preserved["semantic_preview"]["changed_target_count"] == 0
    removed = service.preview(_payload((_layer(),)))
    assert removed["semantic_preview"]["changed_target_count"] == 1

    changed = ExtensionControl(ControlTarget(ControlTargetKind.PERMISSION, fixed.permission_id), ControlState.ENABLED)
    with pytest.raises(ExtensionControlApiError) as error:
        service.preview(_payload((_layer(changed),)))
    assert (error.value.status, error.value.code) == (403, "immutable_permission")


def test_target_level_event_projection_is_redacted_and_rule_aware(tmp_path: Path) -> None:
    permission = _configurable_permission()
    layer = _layer(ExtensionControl(ControlTarget(ControlTargetKind.PERMISSION, permission.permission_id), ControlState.DISABLED))
    service = _service(tmp_path)
    semantic = service.preview(_payload((layer,)))["semantic_preview"]
    targets = service._semantic_event_targets(semantic)

    assert len(targets) == 1
    target = targets[0]
    assert target["kind"] == "permission"
    assert len(target["target_ref"]) == 64
    assert target["target_ref"] != permission.permission_id
    assert set(permission.rule_ids).issubset(set(target["affected_rule_ids"]))
    encoded = json.dumps(targets, sort_keys=True)
    assert permission.permission_id not in encoded
    for secret_marker in ("approval_password", "approval_totp_code", "proof_id", "guard-token", "command_text"):
        assert secret_marker not in encoded


def test_semantic_preview_is_deterministic_and_bounded_json(tmp_path: Path) -> None:
    permission = _configurable_permission()
    layer = _layer(ExtensionControl(ControlTarget(ControlTargetKind.PERMISSION, permission.permission_id), ControlState.DISABLED))
    service = _service(tmp_path)
    first = service.preview(_payload((layer,)))["semantic_preview"]
    second = service.preview(_payload((layer,)))["semantic_preview"]
    assert first == second
    encoded = json.dumps(first, sort_keys=True, separators=(",", ":"))
    assert len(encoded) < 1_000_000
