"""Signed bundle validation followed by negotiated Managed Controls parsing."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from typing import cast

from .managed_controls_policy_fields import (
    ManagedControlsPolicyError,
    ParsedManagedControlsPolicy,
    is_mapping,
    parse_managed_controls_policy_fields,
)
from .policy_bundle_trusted_keys import PolicyBundleVerificationKey
from .policy_bundle_v2 import validated_policy_bundle_v2_payload
from .runtime.command_extensions import CommandSafetyExtensionRegistry
from .runtime.extension_control_authority import (
    ExtensionControlAuthorityError,
    ExtensionControlAuthorityView,
    authenticated_record,
    layers_from_json,
    layers_to_json,
    verify_authenticated_record,
)
from .runtime.extension_control_contract import ControlLayerKind, ExtensionControlLayer

MANAGED_CONTROLS_ACTIVE_STATE_KEY = "managed_controls_active"
MANAGED_CONTROLS_LAST_GOOD_STATE_KEY = "managed_controls_last_good"
MANAGED_CONTROLS_NEGOTIATED_CAPABILITIES_STATE_KEY = "managed_controls_negotiated_capabilities"
MANAGED_CONTROLS_REVISION_STATE_KEY = "managed_controls_revision"
MANAGED_CONTROLS_ACTIVATION_SCHEMA = "guard.managed-controls-activation.v1"
MANAGED_CONTROLS_ACTIVATION_PURPOSE = "managed-controls.activation"
MANAGED_CONTROLS_REVISION_PURPOSE = "managed-controls.revision"


def build_managed_controls_revision_state(
    revision: int,
    *,
    authority_key: bytes,
) -> dict[str, object]:
    """Build an authenticated monotonic epoch for activation and clear publication."""

    if revision < 1:
        raise ValueError("managed controls revision must be positive")
    encoded, digest, mac = authenticated_record(
        {"revision": revision},
        key=authority_key,
        purpose=MANAGED_CONTROLS_REVISION_PURPOSE,
    )
    return {
        "revision": revision,
        "authentication": {"record": encoded, "digest": digest, "mac": mac},
    }


def managed_controls_revision_from_state(
    value: object,
    *,
    authority_key: bytes,
) -> int:
    """Verify and return the durable managed-controls publication epoch."""

    if not is_mapping(value):
        raise ExtensionControlAuthorityError("invalid managed controls revision state")
    revision = value.get("revision")
    authentication = value.get("authentication")
    if not isinstance(revision, int) or isinstance(revision, bool) or revision < 1 or not is_mapping(authentication):
        raise ExtensionControlAuthorityError("invalid managed controls revision state")
    record = authentication.get("record")
    digest = authentication.get("digest")
    mac = authentication.get("mac")
    if not all(isinstance(item, str) for item in (record, digest, mac)):
        raise ExtensionControlAuthorityError("invalid managed controls revision authentication")
    authenticated = verify_authenticated_record(
        cast(str, record),
        expected_digest=cast(str, digest),
        expected_mac=cast(str, mac),
        key=authority_key,
        purpose=MANAGED_CONTROLS_REVISION_PURPOSE,
    )
    if authenticated.get("revision") != revision:
        raise ExtensionControlAuthorityError("managed controls revision payload mismatch")
    return revision


def _projection_digest(value: dict[str, object]) -> str:
    projection = {
        key: item for key, item in value.items() if key not in {"acknowledgement", "authentication", "complete"}
    }
    canonical = json.dumps(projection, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def validated_managed_controls_policy_bundle_v2_payload(
    policy_bundle: dict[str, object],
    *,
    registry: CommandSafetyExtensionRegistry,
    negotiated_capabilities: frozenset[str],
    trusted_verification_keys: tuple[PolicyBundleVerificationKey, ...] = (),
    anchored_verification_keys: tuple[PolicyBundleVerificationKey, ...] = (),
    package_firewall_supported: bool = False,
    now: datetime | None = None,
):
    """Validate the signed envelope first, then parse negotiated Extension semantics."""

    validated, reason = validated_policy_bundle_v2_payload(
        policy_bundle,
        trusted_verification_keys=trusted_verification_keys,
        anchored_verification_keys=anchored_verification_keys,
        now=now,
    )
    if validated is None:
        return None, None, reason
    payload = validated.get("payload")
    if not is_mapping(payload):
        return None, None, "invalid_policy_document"
    try:
        parsed = parse_managed_controls_policy_fields(
            payload,
            registry=registry,
            negotiated_capabilities=negotiated_capabilities,
            package_firewall_supported=package_firewall_supported,
        )
    except ManagedControlsPolicyError as error:
        return None, None, error.code
    except ValueError:
        return None, None, "invalid_extension_semantics"
    return validated, parsed, None


def parsed_managed_controls_from_validated_policy_bundle(
    policy_bundle: dict[str, object],
    *,
    registry: CommandSafetyExtensionRegistry,
    negotiated_capabilities: frozenset[str],
    package_firewall_supported: bool = False,
):
    """Parse Extension semantics from an already authenticated v2 envelope."""

    payload = policy_bundle.get("payload")
    if not is_mapping(payload):
        raise ManagedControlsPolicyError("invalid_policy_document", "Signed policy payload must be an object.")
    return parse_managed_controls_policy_fields(
        payload,
        registry=registry,
        negotiated_capabilities=negotiated_capabilities,
        package_firewall_supported=package_firewall_supported,
    )


def _activation_metadata(
    payload: dict[str, object],
    bundle_version: int,
) -> tuple[object, str | None, str | None]:
    metadata = payload.get("metadata")
    if not is_mapping(metadata):
        return bundle_version, None, None
    candidate_revision = metadata.get("revision")
    revision = (
        candidate_revision
        if isinstance(candidate_revision, (str, int)) and not isinstance(candidate_revision, bool)
        else bundle_version
    )
    candidate_id = metadata.get("id")
    control_set_id = candidate_id.strip()[:160] if isinstance(candidate_id, str) and candidate_id.strip() else None
    candidate_name = metadata.get("name")
    control_set_name = (
        candidate_name.strip()[:160] if isinstance(candidate_name, str) and candidate_name.strip() else None
    )
    return revision, control_set_id, control_set_name


def build_managed_controls_activation_state(
    policy_bundle: dict[str, object],
    parsed: ParsedManagedControlsPolicy,
    *,
    base_authority: ExtensionControlAuthorityView,
    managed_revision: int,
    negotiated_capabilities: frozenset[str],
    authority_key: bytes,
    base_snapshot_digest: str,
) -> dict[str, object]:
    """Build the complete, atomically persisted managed-control projection."""

    if managed_revision < 1:
        raise ValueError("managed_revision must be positive")
    bundle_hash = policy_bundle.get("bundleHash")
    bundle_version = policy_bundle.get("bundleVersion")
    workspace_id = policy_bundle.get("workspaceId")
    payload = policy_bundle.get("payload")
    if not isinstance(bundle_hash, str) or not bundle_hash:
        raise ValueError("managed bundle hash is required")
    if not isinstance(bundle_version, int) or isinstance(bundle_version, bool):
        raise ValueError("managed bundle version is required")
    if not isinstance(workspace_id, str) or not workspace_id:
        raise ValueError("managed workspace binding is required")
    if not is_mapping(payload):
        raise ValueError("managed policy payload is required")
    policy_revision, control_set_id, control_set_name = _activation_metadata(payload, bundle_version)

    signed_layers = () if parsed.signed_cloud_layer is None else (parsed.signed_cloud_layer,)
    rule_targets = [
        {
            "ruleId": target.rule_id,
            "extensionIds": list(target.extension_ids),
            "permissionIds": list(target.permission_ids),
        }
        for target in parsed.rule_targets
    ]
    delegated_targets = [
        {
            "targetKind": target.target.kind.value,
            "targetId": target.target.target_id,
            "enforcementOwner": target.enforcement_owner,
        }
        for target in parsed.delegated_targets
    ]
    activation: dict[str, object] = {
        "schemaVersion": MANAGED_CONTROLS_ACTIVATION_SCHEMA,
        "complete": True,
        "bundleHash": bundle_hash,
        "bundleVersion": bundle_version,
        "workspaceId": workspace_id,
        "catalogDigest": base_authority.catalog_digest,
        "baseAuthorityRevision": base_authority.revision,
        "baseAuthoritySnapshotDigest": base_snapshot_digest,
        "extensionAuthorityRevision": managed_revision,
        "signedCloudLayersJson": layers_to_json(signed_layers),
        "ruleTargets": rule_targets,
        "delegatedTargets": delegated_targets,
        "provenance": {
            "bundleHash": bundle_hash,
            "bundleVersion": bundle_version,
            "payloadHash": policy_bundle.get("payloadHash"),
            "policyRevision": policy_revision,
            "workspaceId": workspace_id,
        },
        "negotiatedCapabilities": sorted(negotiated_capabilities),
    }
    if parsed.authority_mode is not None:
        activation["authorityMode"] = parsed.authority_mode
    if control_set_id is not None:
        activation["controlSetId"] = control_set_id
    if control_set_name is not None:
        activation["controlSetName"] = control_set_name
    for field in ("issuedAt", "expiresAt"):
        candidate = policy_bundle.get(field)
        if isinstance(candidate, str) and candidate.strip():
            activation[field] = candidate.strip()[:80]
    acknowledgement = {
        "bundleHash": bundle_hash,
        "bundleVersion": bundle_version,
        "policyRevision": policy_revision,
        "extensionAuthorityRevision": managed_revision,
        "catalogDigest": base_authority.catalog_digest,
        "effectiveProjectionDigest": _projection_digest(activation),
        "status": "applied",
    }
    activation["acknowledgement"] = acknowledgement
    encoded, digest, mac = authenticated_record(
        {"activation": activation},
        key=authority_key,
        purpose=MANAGED_CONTROLS_ACTIVATION_PURPOSE,
    )
    activation["authentication"] = {
        "record": encoded,
        "digest": digest,
        "mac": mac,
    }
    return activation


def managed_controls_layers_from_activation_state(
    value: object,
    *,
    catalog_digest: str,
    authority_key: bytes,
) -> tuple[tuple[ExtensionControlLayer, ...], int]:
    """Load only a complete, internally consistent managed activation snapshot."""

    if not is_mapping(value) or value.get("schemaVersion") != MANAGED_CONTROLS_ACTIVATION_SCHEMA:
        raise ExtensionControlAuthorityError("invalid managed controls activation state")
    if value.get("complete") is not True or value.get("catalogDigest") != catalog_digest:
        raise ExtensionControlAuthorityError("incomplete managed controls activation state")
    authentication = value.get("authentication")
    if not is_mapping(authentication):
        raise ExtensionControlAuthorityError("missing managed controls activation authentication")
    record = authentication.get("record")
    digest = authentication.get("digest")
    mac = authentication.get("mac")
    if not all(isinstance(item, str) for item in (record, digest, mac)):
        raise ExtensionControlAuthorityError("invalid managed controls activation authentication")
    authenticated = verify_authenticated_record(
        cast(str, record),
        expected_digest=cast(str, digest),
        expected_mac=cast(str, mac),
        key=authority_key,
        purpose=MANAGED_CONTROLS_ACTIVATION_PURPOSE,
    )
    unsigned = dict(value)
    unsigned.pop("authentication", None)
    if authenticated.get("activation") != unsigned:
        raise ExtensionControlAuthorityError("managed controls activation payload mismatch")
    revision = value.get("extensionAuthorityRevision")
    encoded_layers = value.get("signedCloudLayersJson")
    acknowledgement = value.get("acknowledgement")
    if not isinstance(revision, int) or isinstance(revision, bool) or revision < 1:
        raise ExtensionControlAuthorityError("invalid managed controls activation revision")
    if not isinstance(encoded_layers, str) or not is_mapping(acknowledgement):
        raise ExtensionControlAuthorityError("invalid managed controls activation projection")
    if (
        acknowledgement.get("bundleHash") != value.get("bundleHash")
        or acknowledgement.get("bundleVersion") != value.get("bundleVersion")
        or acknowledgement.get("extensionAuthorityRevision") != revision
        or acknowledgement.get("catalogDigest") != catalog_digest
        or acknowledgement.get("effectiveProjectionDigest") != _projection_digest(unsigned)
    ):
        raise ExtensionControlAuthorityError("managed controls acknowledgement mismatch")
    layers = layers_from_json(encoded_layers)
    if len(layers) > 1 or any(layer.kind is not ControlLayerKind.SIGNED_CLOUD for layer in layers):
        raise ExtensionControlAuthorityError("invalid managed signed Cloud layer")
    return cast(tuple[ExtensionControlLayer, ...], layers), revision
