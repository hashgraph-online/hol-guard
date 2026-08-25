"""Strict correlation of managed policy deliveries to signed bundle authority."""

from __future__ import annotations

import re
from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Literal
from uuid import UUID

from .policy_bundle_v2 import POLICY_BUNDLE_V2_CONTRACT, validated_policy_bundle_v2_acknowledgement

_DELIVERY_KEYS = frozenset(
    {
        "bundleId",
        "bundleHash",
        "bundleVersion",
        "workspaceId",
        "deviceId",
        "runtimeSessionId",
        "deliveryId",
        "policyRevision",
        "extensionAuthorityRevision",
        "catalogDigest",
        "effectiveProjectionDigest",
        "lastKnownGoodBundleHash",
    }
)
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_CATALOG_DIGEST = re.compile(r"^[0-9a-f]{64}$")


def policy_bundle_has_extension_semantics(policy_bundle: Mapping[str, object]) -> bool:
    payload = policy_bundle.get("payload")
    if not isinstance(payload, dict):
        return False
    if "x-hol-extension-controls" in payload:
        return True
    spec = payload.get("spec")
    if not isinstance(spec, dict):
        return False
    rules = spec.get("rules")
    return isinstance(rules, list) and any(
        isinstance(rule, dict) and "x-hol-extension-targets" in rule for rule in rules
    )


def _bounded_string(value: object, *, maximum: int = 128) -> str | None:
    if not isinstance(value, str) or not value or value != value.strip():
        return None
    return value if len(value.encode("utf-8")) <= maximum else None


def _positive_integer(value: object) -> int | None:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        return None
    return value


def _canonical_uuid(value: object) -> str | None:
    candidate = _bounded_string(value)
    if candidate is None:
        return None
    try:
        parsed = UUID(candidate)
    except ValueError:
        return None
    return candidate if str(parsed) == candidate else None


def validate_policy_bundle_delivery(
    value: object,
    *,
    policy_bundle: Mapping[str, object],
    workspace_id: str | None,
    device_id: str,
    runtime_summary: object,
) -> tuple[dict[str, object] | None, str | None]:
    """Validate an exact delivery object and bind it to signed/local authority."""

    if not isinstance(value, dict):
        return None, "missing_policy_bundle_delivery"
    if set(value) != _DELIVERY_KEYS:
        return None, "invalid_policy_bundle_delivery_fields"

    string_fields = ("bundleId", "workspaceId", "deviceId", "runtimeSessionId")
    if any(_bounded_string(value.get(field)) is None for field in string_fields):
        return None, "invalid_policy_bundle_delivery"
    if _canonical_uuid(value.get("deliveryId")) is None:
        return None, "invalid_policy_bundle_delivery"
    if _SHA256.fullmatch(str(value.get("bundleHash"))) is None:
        return None, "invalid_policy_bundle_delivery"
    if _SHA256.fullmatch(str(value.get("effectiveProjectionDigest"))) is None:
        return None, "invalid_policy_bundle_delivery"
    last_good_hash = value.get("lastKnownGoodBundleHash")
    if last_good_hash is not None and (
        not isinstance(last_good_hash, str) or _SHA256.fullmatch(last_good_hash) is None
    ):
        return None, "invalid_policy_bundle_delivery"
    catalog_digest = value.get("catalogDigest")
    if not isinstance(catalog_digest, str) or _CATALOG_DIGEST.fullmatch(catalog_digest) is None:
        return None, "invalid_policy_bundle_delivery"
    if any(
        _positive_integer(value.get(field)) is None
        for field in ("bundleVersion", "policyRevision", "extensionAuthorityRevision")
    ):
        return None, "invalid_policy_bundle_delivery"

    payload = policy_bundle.get("payload")
    metadata = payload.get("metadata") if isinstance(payload, dict) else None
    policy_revision = metadata.get("revision") if isinstance(metadata, dict) else None
    rollback = policy_bundle.get("rollback")
    signed_last_good_hash = rollback.get("lastGoodBundleHash") if isinstance(rollback, dict) else None
    expected = {
        "bundleHash": policy_bundle.get("bundleHash"),
        "bundleVersion": policy_bundle.get("bundleVersion"),
        "workspaceId": policy_bundle.get("workspaceId"),
        "deviceId": device_id,
        "policyRevision": policy_revision,
        "effectiveProjectionDigest": policy_bundle.get("payloadHash"),
        "lastKnownGoodBundleHash": signed_last_good_hash,
    }
    if workspace_id is None or expected["workspaceId"] != workspace_id:
        return None, "policy_bundle_delivery_mismatch"
    if any(value.get(field) != expected_value for field, expected_value in expected.items()):
        return None, "policy_bundle_delivery_mismatch"
    if not isinstance(runtime_summary, dict):
        return None, "policy_bundle_delivery_runtime_unavailable"
    if value.get("runtimeSessionId") != runtime_summary.get("runtime_session_id"):
        return None, "policy_bundle_delivery_mismatch"
    if runtime_summary.get("runtime_device_id") not in {None, device_id}:
        return None, "policy_bundle_delivery_mismatch"
    if runtime_summary.get("extensionCatalogDigest") != catalog_digest:
        return None, "policy_bundle_delivery_mismatch"
    if runtime_summary.get("extensionAuthorityRevision") != value.get("extensionAuthorityRevision"):
        return None, "policy_bundle_delivery_mismatch"
    return dict(value), None


def validated_managed_policy_delivery(
    *,
    policy_bundle: dict[str, object],
    delivery_field_provided: bool,
    delivery_payload: object,
    workspace_id: str | None,
    device_id: str,
    runtime_summary: object,
) -> tuple[dict[str, object] | None, str | None]:
    """Validate delivery metadata only when a V2 bundle carries Extension semantics."""

    if policy_bundle.get("contractVersion") != POLICY_BUNDLE_V2_CONTRACT:
        return None, None
    if not policy_bundle_has_extension_semantics(policy_bundle):
        return None, None
    if not delivery_field_provided:
        return None, "missing_policy_bundle_delivery"
    return validate_policy_bundle_delivery(
        delivery_payload,
        policy_bundle=policy_bundle,
        workspace_id=workspace_id,
        device_id=device_id,
        runtime_summary=runtime_summary,
    )


def policy_bundle_acknowledgement_payload(
    *,
    device_id: str,
    device_name: str,
    policy_bundle: dict[str, object],
    synced_at: str,
    status: Literal["validated", "applied"] = "applied",
    previous: dict[str, object] | None = None,
    delivery: dict[str, object] | None = None,
) -> dict[str, object]:
    """Build a legacy acknowledgement or an exact delivery-bound V2 acknowledgement."""

    if policy_bundle.get("contractVersion") != POLICY_BUNDLE_V2_CONTRACT:
        return {
            "appliedAt": synced_at,
            "bundleHash": policy_bundle["bundleHash"],
            "bundleVersion": policy_bundle["bundleVersion"],
            "deviceId": device_id,
            "deviceName": device_name,
            "status": "synced",
        }
    if delivery is None:
        return {}
    identity_fields = (
        "workspaceId",
        "deviceId",
        "deliveryId",
        "runtimeSessionId",
        "bundleId",
        "bundleVersion",
        "bundleHash",
        "policyRevision",
        "extensionAuthorityRevision",
        "catalogDigest",
        "effectiveProjectionDigest",
        "lastKnownGoodBundleHash",
    )
    candidate_identity = {field: delivery[field] for field in identity_fields}
    matching_previous = (
        previous
        if previous is not None and all(previous.get(field) == candidate_identity[field] for field in identity_fields)
        else None
    )
    previous_sequence = matching_previous.get("sequence") if matching_previous is not None else None
    resolved_status = (
        "applied"
        if status == "applied" or (matching_previous is not None and matching_previous.get("status") == "applied")
        else "validated"
    )
    acknowledgement = {
        "contractVersion": POLICY_BUNDLE_V2_CONTRACT,
        **candidate_identity,
        "sequence": previous_sequence + 1 if isinstance(previous_sequence, int) else 1,
        "status": resolved_status,
        "observedAt": _normalized_observed_at(synced_at),
    }
    validated, error = validated_policy_bundle_v2_acknowledgement(acknowledgement, previous=matching_previous)
    if validated is None:
        raise ValueError(error or "invalid_policy_bundle_acknowledgement")
    return validated


def _normalized_observed_at(value: str) -> str:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return value
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def effective_policy_bundle_acknowledgement(
    *,
    device_id: str,
    device_name: str,
    effective_policy_bundle: dict[str, object],
    validated_policy_bundle: dict[str, object] | None,
    validated_delivery: dict[str, object] | None,
    stored_acknowledgement: object,
    synced_at: str,
) -> dict[str, object]:
    """Select the exact acknowledgement for a newly activated or retained bundle."""

    if effective_policy_bundle.get("contractVersion") != POLICY_BUNDLE_V2_CONTRACT:
        return policy_bundle_acknowledgement_payload(
            device_id=device_id,
            device_name=device_name,
            policy_bundle=effective_policy_bundle,
            synced_at=synced_at,
        )
    activating_new_bundle = validated_policy_bundle is not None and effective_policy_bundle.get(
        "bundleHash"
    ) == validated_policy_bundle.get("bundleHash")
    previous = stored_acknowledgement if isinstance(stored_acknowledgement, dict) else None
    if not activating_new_bundle:
        return dict(previous) if previous is not None else {}
    return policy_bundle_acknowledgement_payload(
        device_id=device_id,
        device_name=device_name,
        policy_bundle=effective_policy_bundle,
        synced_at=synced_at,
        previous=previous,
        delivery=validated_delivery,
    )
