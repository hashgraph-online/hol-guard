"""Strict correlation of managed policy deliveries to signed bundle authority."""

from __future__ import annotations

import re
from collections.abc import Mapping
from uuid import UUID

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
