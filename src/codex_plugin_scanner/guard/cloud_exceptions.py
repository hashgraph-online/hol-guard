"""Cloud exception DTO parsing and storage helpers (HGLP046-HGLP060)."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Any, TypeGuard

from .models import (
    CloudException,
    CloudExceptionAckStatus,
    CloudExceptionEffect,
    CloudExceptionProvenance,
    CloudExceptionScope,
)

_CLOUD_EXCEPTION_SCOPES: tuple[CloudExceptionScope, ...] = ("artifact", "publisher", "harness", "workspace", "global")
_CLOUD_EXCEPTION_EFFECTS: tuple[CloudExceptionEffect, ...] = ("allow",)
_CLOUD_EXCEPTION_ACK_STATUSES: tuple[CloudExceptionAckStatus, ...] = ("pending", "synced", "failed", "offline")
_CLOUD_EXCEPTION_PROVENANCE_VALUES: tuple[CloudExceptionProvenance, ...] = ("receipt-sync", "policy-bundle")


def _non_empty_string(value: object) -> str | None:
    return value if isinstance(value, str) and value.strip() else None


def _is_cloud_exception_scope(value: object) -> TypeGuard[CloudExceptionScope]:
    return isinstance(value, str) and value in _CLOUD_EXCEPTION_SCOPES


def _is_cloud_exception_effect(value: object) -> TypeGuard[CloudExceptionEffect]:
    return isinstance(value, str) and value in _CLOUD_EXCEPTION_EFFECTS


def _is_cloud_exception_ack_status(value: object) -> TypeGuard[CloudExceptionAckStatus]:
    return isinstance(value, str) and value in _CLOUD_EXCEPTION_ACK_STATUSES


def _is_cloud_exception_provenance(value: object) -> TypeGuard[CloudExceptionProvenance]:
    return isinstance(value, str) and value in _CLOUD_EXCEPTION_PROVENANCE_VALUES


def _parse_iso_timestamp(value: object) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    normalized = value.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed


def _normalized_timestamp_string(value: object) -> str | None:
    parsed = _parse_iso_timestamp(value)
    if parsed is None:
        return None
    return parsed.astimezone(timezone.utc).isoformat()


def _cloud_exception_is_active(item: CloudException, *, now: str | None = None) -> bool:
    expiry = _parse_iso_timestamp(item.expiry)
    if expiry is None:
        return False
    current = _parse_iso_timestamp(now or datetime.now(timezone.utc).isoformat())
    if current is None:
        return False
    return expiry > current


def _resolve_cloud_exception_ack_status(
    *,
    device_id: str | None,
    policy_bundle: dict[str, object] | None,
    policy_bundle_ack: dict[str, object] | None,
) -> CloudExceptionAckStatus | None:
    if isinstance(policy_bundle_ack, dict) and isinstance(policy_bundle, dict) and device_id is not None:
        ack_status = policy_bundle_ack.get("status")
        bundle_hash = _non_empty_string(policy_bundle.get("bundleHash"))
        bundle_version = _non_empty_string(policy_bundle.get("bundleVersion"))
        if (
            _is_cloud_exception_ack_status(ack_status)
            and bundle_hash is not None
            and bundle_version is not None
            and policy_bundle_ack.get("bundleHash") == bundle_hash
            and policy_bundle_ack.get("bundleVersion") == bundle_version
            and policy_bundle_ack.get("deviceId") == device_id
            and _normalized_timestamp_string(policy_bundle_ack.get("appliedAt")) is not None
        ):
            return ack_status
    if not isinstance(policy_bundle, dict):
        return None
    acknowledgements = policy_bundle.get("acknowledgements")
    if not isinstance(acknowledgements, list) or device_id is None:
        return None
    for acknowledgement in acknowledgements:
        if not isinstance(acknowledgement, dict):
            continue
        if str(acknowledgement.get("deviceId")) != device_id:
            continue
        status = acknowledgement.get("status")
        if _is_cloud_exception_ack_status(status):
            return status
    return None


def cloud_exception_from_mapping(
    item: dict[str, object],
    *,
    bundle_hash: str | None = None,
    ack_status: CloudExceptionAckStatus | None = None,
    rejection_reason: str | None = None,
    provenance: CloudExceptionProvenance = "receipt-sync",
) -> CloudException | None:
    exception_id = _non_empty_string(item.get("exceptionId") or item.get("id"))
    if exception_id is None:
        return None
    scope_value = item.get("scope")
    if not _is_cloud_exception_scope(scope_value):
        return None
    scope = scope_value
    effect_value = item.get("effect") or "allow"
    if not _is_cloud_exception_effect(effect_value):
        return None
    effect = effect_value
    owner = _non_empty_string(item.get("owner"))
    expiry = _normalized_timestamp_string(item.get("expiresAt") or item.get("expiry"))
    if owner is None or expiry is None:
        return None
    harness_value = item.get("harness")
    harness = harness_value if isinstance(harness_value, str) and harness_value.strip() else None
    if scope == "harness" and harness is None:
        return None
    approver = _non_empty_string(item.get("approver"))
    source_receipt_id = _non_empty_string(item.get("sourceReceiptId") or item.get("source_receipt_id"))
    last_used_at = _normalized_timestamp_string(item.get("lastUsedAt") or item.get("last_used_at"))
    resolved_ack = ack_status or _non_empty_string(item.get("ackStatus") or item.get("ack_status"))
    if resolved_ack is not None and not _is_cloud_exception_ack_status(resolved_ack):
        resolved_ack = None
    resolved_bundle_hash = _non_empty_string(item.get("bundleHash") or item.get("bundle_hash")) or bundle_hash
    resolved_provenance = provenance if _is_cloud_exception_provenance(provenance) else "receipt-sync"
    return CloudException(
        id=exception_id,
        effect=effect,
        scope=scope,
        harness=harness,
        owner=owner,
        approver=approver,
        expiry=expiry,
        source_receipt_id=source_receipt_id,
        bundle_hash=resolved_bundle_hash,
        ack_status=resolved_ack,
        last_used_at=last_used_at,
        rejection_reason=(
            _non_empty_string(item.get("rejectionReason") or item.get("rejection_reason")) or rejection_reason
        ),
        provenance=resolved_provenance,
    )


def build_cloud_exceptions_from_policy_bundle(
    policy_bundle: dict[str, object],
    *,
    device_id: str | None = None,
    policy_bundle_ack: dict[str, object] | None = None,
) -> list[CloudException]:
    cloud_exceptions = policy_bundle.get("cloudExceptions")
    if not isinstance(cloud_exceptions, list):
        return []
    bundle_hash = _non_empty_string(policy_bundle.get("bundleHash"))
    ack_status = _resolve_cloud_exception_ack_status(
        device_id=device_id,
        policy_bundle=policy_bundle,
        policy_bundle_ack=policy_bundle_ack,
    )
    items: list[CloudException] = []
    for raw_item in cloud_exceptions:
        if not isinstance(raw_item, dict):
            continue
        parsed = cloud_exception_from_mapping(
            raw_item,
            bundle_hash=bundle_hash,
            ack_status=ack_status,
            provenance="policy-bundle",
        )
        if parsed is not None:
            items.append(parsed)
    return items


def dedupe_cloud_exceptions(items: list[CloudException]) -> list[CloudException]:
    deduped: dict[str, CloudException] = {}
    for item in items:
        deduped[item.id] = item
    return list(deduped.values())


def list_active_cloud_exceptions(
    items: list[CloudException],
    *,
    harness: str | None = None,
    now: str | None = None,
) -> list[CloudException]:
    active = [item for item in items if _cloud_exception_is_active(item, now=now)]
    if harness is None:
        return active
    # An exception that names no harness applies to every harness.
    return [item for item in active if item.harness in {None, harness, "*"}]


_SCOPE_TARGET_KEYS: dict[str, tuple[str, ...]] = {
    "artifact": ("artifactId",),
    "publisher": ("publisher",),
    "workspace": ("workingDirectory", "workspaceId"),
}
# Position of the action in a policy-bundle decision identity
# (``_cached_policy_bundle_decision_identities``, ``store_policy.py``).
_IDENTITY_ACTION_INDEX = 6


def _cloud_exception_matches(
    item: CloudException,
    raw_item: Mapping[str, object],
    *,
    harness: str,
    artifact_id: str | None,
    publisher: str | None,
    workspace: str | None,
    bundle_workspace_id: str | None,
) -> bool:
    if item.harness not in {None, "*", harness}:
        return False
    legacy = _cloud_exception_legacy_scope_field(item)
    targets = {
        "artifactId": _non_empty_string(raw_item.get("artifactId")),
        "publisher": _non_empty_string(raw_item.get("publisher")),
        "workingDirectory": _non_empty_string(raw_item.get("workingDirectory")),
        "workspaceId": _non_empty_string(raw_item.get("workspaceId")),
    }
    if legacy is not None:
        legacy_key = "artifactId" if legacy[0] == "artifact_id" else "publisher"
        targets[legacy_key] = targets[legacy_key] or legacy[1]
    # The scope's own target must be named; an exception that names no
    # artifact cannot stand in for an artifact exception.
    required = _SCOPE_TARGET_KEYS.get(item.scope, ())
    if required and all(targets[key] is None for key in required):
        return False
    # A Cloud workspace id must be the workspace that signed the bundle.
    if targets["workspaceId"] is not None and targets["workspaceId"] != bundle_workspace_id:
        return False
    # Every device-side target the exception names narrows it.
    observed = {"artifactId": artifact_id, "publisher": publisher, "workingDirectory": workspace}
    return all(targets[key] is None or targets[key] == value for key, value in observed.items())


def cloud_exception_lifting_policy_bundle(
    policy_bundle: Mapping[str, object],
    *,
    harness: str,
    artifact_id: str | None,
    publisher: str | None,
    workspace: str | None,
    now: str | None,
) -> str | None:
    """Return the approved Cloud exception that lifts the bundle's rules for this target.

    An exception approved in Guard Cloud is an allow for the policy that Cloud
    published, so it lifts only rules from that same verified bundle. When an
    id repeats, the last entry wins, as in ``dedupe_cloud_exceptions``.
    """

    raw_items = policy_bundle.get("cloudExceptions")
    if not isinstance(raw_items, list):
        return None
    latest: dict[str, tuple[CloudException, Mapping[str, object]]] = {}
    for raw_item in raw_items:
        if not isinstance(raw_item, dict):
            continue
        item = cloud_exception_from_mapping(raw_item, provenance="policy-bundle")
        if item is not None:
            latest[item.id] = (item, raw_item)
    bundle_workspace_id = _non_empty_string(policy_bundle.get("workspaceId"))
    for item, raw_item in latest.values():
        if item.effect != "allow" or not _cloud_exception_is_active(item, now=now):
            continue
        if _cloud_exception_matches(
            item,
            raw_item,
            harness=harness,
            artifact_id=artifact_id,
            publisher=publisher,
            workspace=workspace,
            bundle_workspace_id=bundle_workspace_id,
        ):
            return item.id
    return None


def lift_cloud_excepted_policy_bundle_identities(
    identities: list[list[Any]] | None,
    policy_bundle: Mapping[str, object] | None,
    *,
    harness: str,
    artifact_id: str | None,
    publisher: str | None,
    workspace: str | None,
    now: str,
) -> list[list[Any]] | None:
    """Drop the bundle's non-allow rule identities when an approved exception covers this target.

    The native lookup honors a saved ``policy-bundle`` row only while its
    identity is listed, so a lifted Cloud rule no longer applies to this one
    lookup and the lookup ranks the remaining local rows as it would without it.
    """

    if not identities or policy_bundle is None:
        return identities
    exception_id = cloud_exception_lifting_policy_bundle(
        policy_bundle,
        harness=harness,
        artifact_id=artifact_id,
        publisher=publisher,
        workspace=workspace,
        now=now,
    )
    if exception_id is None:
        return identities
    return [identity for identity in identities if identity[_IDENTITY_ACTION_INDEX] == "allow"]


def _cloud_exception_legacy_scope_field(item: CloudException) -> tuple[str, str] | None:
    prefix = f"{item.scope}:"
    if not item.id.startswith(prefix):
        return None
    value = item.id[len(prefix) :]
    if not value.strip():
        return None
    if item.scope == "artifact":
        return ("artifact_id", value)
    if item.scope == "publisher":
        return ("publisher", value)
    return None


def cloud_exception_to_dict(item: CloudException) -> dict[str, object]:
    payload = asdict(item)
    payload["expires_at"] = item.expiry
    legacy_scope_field = _cloud_exception_legacy_scope_field(item)
    if legacy_scope_field is not None:
        field_name, field_value = legacy_scope_field
        payload[field_name] = field_value
    return payload
