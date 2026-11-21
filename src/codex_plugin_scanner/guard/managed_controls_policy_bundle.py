"""Signed bundle validation followed by negotiated Managed Controls parsing."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Mapping
from pathlib import Path

from .managed_controls_policy_fields import (
    _UNBOUND,
    ManagedControlsPolicyError,
    ParsedManagedControlsPolicy,
    is_mapping,
    parse_managed_controls_policy_fields,
)
from .native_extension_control_authority import layers_to_wire
from .runtime.command_extensions import CommandSafetyExtensionRegistry
from .runtime.extension_control_authority import (
    ExtensionControlAuthorityView,
    layers_to_json,
)
from .runtime.extension_control_contract import ExtensionControlLayer

MANAGED_CONTROLS_ACTIVE_STATE_KEY = "managed_controls_active"
MANAGED_CONTROLS_LAST_GOOD_STATE_KEY = "managed_controls_last_good"
MANAGED_CONTROLS_NEGOTIATED_CAPABILITIES_STATE_KEY = "managed_controls_negotiated_capabilities"
MANAGED_CONTROLS_REVISION_STATE_KEY = "managed_controls_revision"
MANAGED_CONTROLS_ACTIVATION_PURPOSE = "managed-controls.activation"


def _rule_targets_wire(parsed: ParsedManagedControlsPolicy) -> list[object]:
    return [
        {
            "ruleId": target.rule_id,
            "extensionIds": list(target.extension_ids),
            "permissionIds": list(target.permission_ids),
        }
        for target in parsed.rule_targets
    ]


def _delegated_targets_wire(parsed: ParsedManagedControlsPolicy) -> list[object]:
    return [
        {
            "targetKind": target.target.kind.value,
            "targetId": target.target.target_id,
            "enforcementOwner": target.enforcement_owner,
        }
        for target in parsed.delegated_targets
    ]


def _observed_projection(parsed, projection: str, *, catalog_digest: str | None) -> str:
    """Release a native projection only under the enforcement identity it was cut against."""

    if catalog_digest != parsed.cloud_enforcement_digest:
        raise ManagedControlsPolicyError(
            "policy_enforcement_digest_mismatch", "Cloud policy enforcement identity changed."
        )
    return projection


def signed_cloud_extension_projection_json(
    parsed: ParsedManagedControlsPolicy,
    *,
    catalog_digest: str,
) -> str:
    """Return the canonical signed-Cloud projection for the observed wire catalog."""

    if parsed.cloud_projection_json is not None:
        return _observed_projection(parsed, parsed.cloud_projection_json, catalog_digest=catalog_digest)

    signed_layers = ()
    if parsed.signed_cloud_layer is not None:
        layer = parsed.signed_cloud_layer
        signed_layers = (
            ExtensionControlLayer(
                layer.schema_version,
                layer.kind,
                catalog_digest,
                layer.global_lockdown,
                layer.controls,
            ),
        )
    projection = {
        "schemaVersion": "guard.signed-cloud-extension-projection.v1",
        "authorityMode": parsed.authority_mode,
        "signedCloudLayersJson": layers_to_json(signed_layers),
        "ruleTargets": _rule_targets_wire(parsed),
        "delegatedTargets": _delegated_targets_wire(parsed),
    }
    return json.dumps(projection, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def signed_cloud_extension_projection_digest(
    parsed: ParsedManagedControlsPolicy,
    *,
    catalog_digest: str,
) -> str:
    """Hash the canonical signed-Cloud projection for the observed wire catalog."""

    if parsed.cloud_projection_digest is not None:
        return _observed_projection(parsed, parsed.cloud_projection_digest, catalog_digest=catalog_digest)

    canonical = signed_cloud_extension_projection_json(parsed, catalog_digest=catalog_digest)
    return f"sha256:{hashlib.sha256(canonical.encode('utf-8')).hexdigest()}"


def parsed_managed_controls_from_validated_policy_bundle(
    policy_bundle: dict[str, object],
    *,
    registry: CommandSafetyExtensionRegistry | Callable[[], CommandSafetyExtensionRegistry],
    negotiated_capabilities: frozenset[str],
    package_firewall_supported: bool = False,
    guard_home: Path | None = None,
    runtime_summary: dict[str, object] | None = None,
    delivery_catalog_digest: object = _UNBOUND,
):
    """Parse Extension semantics from an already authenticated v2 envelope."""

    payload = policy_bundle.get("payload")
    if not is_mapping(payload):
        raise ManagedControlsPolicyError("invalid_policy_document", "Signed policy payload must be an object.")

    def cloud_view(resolved_registry):
        capabilities = runtime_summary.get("managedControlsCapabilities") if runtime_summary is not None else None
        if runtime_summary is None or not (isinstance(capabilities, list) and "extension-catalog.v2" in capabilities):
            return None
        if guard_home is None:
            raise ManagedControlsPolicyError("policy_local_view_missing", "An explicit local policy view is required.")
        from .runtime.extension_catalog_completion import local_policy_view

        try:
            return local_policy_view(
                guard_home=guard_home,
                runtime_summary=runtime_summary,
                registry=resolved_registry,
                policy_workspace_id=policy_bundle.get("workspaceId"),
            )
        except ManagedControlsPolicyError:
            raise
        except (ImportError, OSError, RuntimeError, TypeError, ValueError) as error:
            raise ManagedControlsPolicyError(
                "policy_local_view_invalid", "The local policy view could not be authenticated."
            ) from error

    return parse_managed_controls_policy_fields(
        payload,
        registry=registry,
        negotiated_capabilities=negotiated_capabilities,
        package_firewall_supported=package_firewall_supported,
        guard_home=guard_home,
        cloud_view=cloud_view,
        delivery_catalog_digest=delivery_catalog_digest,
    )


_ACTIVATION_BUNDLE_FIELDS = ("bundleHash", "bundleVersion", "workspaceId", "payloadHash", "issuedAt", "expiresAt")


def _activation_metadata_wire(metadata: object) -> object:
    """Only the metadata the resident reads, so unrelated values cannot break the request hash."""

    if not is_mapping(metadata):
        return None
    return {name: metadata[name] for name in ("revision", "id", "name") if name in metadata}


def managed_controls_activation_input(
    policy_bundle: Mapping[str, object],
    parsed: ParsedManagedControlsPolicy,
    *,
    base_authority: ExtensionControlAuthorityView,
    managed_revision: int,
    negotiated_capabilities: frozenset[str],
    base_snapshot_digest: str,
) -> dict[str, object]:
    """The verified policy the resident builds, acknowledges and seals into an activation."""

    bundle: dict[str, object] = {name: policy_bundle.get(name) for name in _ACTIVATION_BUNDLE_FIELDS}
    payload = policy_bundle.get("payload")
    bundle["payload"] = (
        {"metadata": _activation_metadata_wire(payload.get("metadata"))} if is_mapping(payload) else None
    )
    signed_layers = () if parsed.signed_cloud_layer is None else (parsed.signed_cloud_layer,)
    activation: dict[str, object] = {
        "bundle": bundle,
        "signed_cloud_layers": layers_to_wire(signed_layers),
        "rule_targets": _rule_targets_wire(parsed),
        "delegated_targets": _delegated_targets_wire(parsed),
        "base_revision": base_authority.revision,
        "base_snapshot_digest": base_snapshot_digest,
        "managed_revision": managed_revision,
        "negotiated_capabilities": sorted(negotiated_capabilities),
    }
    if parsed.authority_mode is not None:
        activation["authority_mode"] = parsed.authority_mode
    return activation
