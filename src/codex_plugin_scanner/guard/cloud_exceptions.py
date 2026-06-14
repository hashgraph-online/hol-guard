"""Cloud exception DTO parsing and storage helpers (HGLP046-HGLP060)."""

from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timezone

from .models import CloudException

_CLOUD_EXCEPTION_SCOPES = frozenset({"artifact", "publisher", "harness", "workspace", "global"})
_CLOUD_EXCEPTION_EFFECTS = frozenset({"allow"})
_CLOUD_EXCEPTION_ACK_STATUSES = frozenset({"pending", "synced", "failed", "offline"})


def _non_empty_string(value: object) -> str | None:
    return value if isinstance(value, str) and value.strip() else None


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


def _policy_bundle_cloud_exception_is_valid(item: object) -> bool:
    if not isinstance(item, dict):
        return False
    exception_id = _non_empty_string(item.get("exceptionId") or item.get("id"))
    if exception_id is None:
        return False
    effect = item.get("effect") or "allow"
    if effect not in _CLOUD_EXCEPTION_EFFECTS:
        return False
    scope = item.get("scope")
    if scope not in _CLOUD_EXCEPTION_SCOPES:
        return False
    if _non_empty_string(item.get("owner")) is None:
        return False
    if _normalized_timestamp_string(item.get("expiresAt") or item.get("expiry")) is None:
        return False
    harness = item.get("harness")
    if scope == "harness":
        if not isinstance(harness, str) or not harness.strip():
            return False
    elif harness is not None and not isinstance(harness, str):
        return False
    approver = item.get("approver")
    if approver is not None and _non_empty_string(approver) is None:
        return False
    source_receipt_id = item.get("sourceReceiptId")
    return source_receipt_id is None or _non_empty_string(source_receipt_id) is not None


def policy_bundle_cloud_exceptions_are_valid(policy_bundle: dict[str, object]) -> bool:
    cloud_exceptions = policy_bundle.get("cloudExceptions")
    if cloud_exceptions is None:
        return True
    if not isinstance(cloud_exceptions, list):
        return False
    return all(_policy_bundle_cloud_exception_is_valid(item) for item in cloud_exceptions)


def _resolve_cloud_exception_ack_status(
    *,
    device_id: str | None,
    policy_bundle: dict[str, object] | None,
    policy_bundle_ack: dict[str, object] | None,
) -> str | None:
    if isinstance(policy_bundle_ack, dict):
        ack_status = policy_bundle_ack.get("status")
        if isinstance(ack_status, str) and ack_status in _CLOUD_EXCEPTION_ACK_STATUSES:
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
        if isinstance(status, str) and status in _CLOUD_EXCEPTION_ACK_STATUSES:
            return status
    return None


def cloud_exception_from_mapping(
    item: dict[str, object],
    *,
    bundle_hash: str | None = None,
    ack_status: str | None = None,
    rejection_reason: str | None = None,
    provenance: str = "receipt-sync",
) -> CloudException | None:
    exception_id = _non_empty_string(item.get("exceptionId") or item.get("id"))
    if exception_id is None:
        return None
    scope = item.get("scope")
    if scope not in _CLOUD_EXCEPTION_SCOPES:
        return None
    effect = item.get("effect") or "allow"
    if effect not in _CLOUD_EXCEPTION_EFFECTS:
        return None
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
    if resolved_ack is not None and resolved_ack not in _CLOUD_EXCEPTION_ACK_STATUSES:
        resolved_ack = None
    resolved_bundle_hash = _non_empty_string(item.get("bundleHash") or item.get("bundle_hash")) or bundle_hash
    return CloudException(
        id=exception_id,
        effect=effect,  # type: ignore[arg-type]
        scope=scope,  # type: ignore[arg-type]
        harness=harness,
        owner=owner,
        approver=approver,
        expiry=expiry,
        source_receipt_id=source_receipt_id,
        bundle_hash=resolved_bundle_hash,
        ack_status=resolved_ack,  # type: ignore[arg-type]
        last_used_at=last_used_at,
        rejection_reason=(
            _non_empty_string(item.get("rejectionReason") or item.get("rejection_reason"))
            or rejection_reason
        ),
        provenance=(
            provenance if provenance in {"receipt-sync", "policy-bundle"} else "receipt-sync"
        ),  # type: ignore[arg-type]
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


def cloud_exception_from_stored_dict(item: dict[str, object]) -> CloudException | None:
    exception_id = _non_empty_string(item.get("id"))
    if exception_id is None:
        return None
    scope = item.get("scope")
    if scope not in _CLOUD_EXCEPTION_SCOPES:
        return None
    effect = item.get("effect") or "allow"
    if effect not in _CLOUD_EXCEPTION_EFFECTS:
        return None
    owner = _non_empty_string(item.get("owner"))
    expiry = _normalized_timestamp_string(item.get("expiry"))
    if owner is None or expiry is None:
        return None
    harness_value = item.get("harness")
    harness = harness_value if isinstance(harness_value, str) and harness_value.strip() else None
    if scope == "harness" and harness is None:
        return None
    ack_status = item.get("ack_status")
    if ack_status is not None and ack_status not in _CLOUD_EXCEPTION_ACK_STATUSES:
        ack_status = None
    resolved_provenance = item.get("provenance")
    if resolved_provenance not in {"receipt-sync", "policy-bundle"}:
        resolved_provenance = "receipt-sync"
    return CloudException(
        id=exception_id,
        effect=effect,  # type: ignore[arg-type]
        scope=scope,  # type: ignore[arg-type]
        harness=harness,
        owner=owner,
        approver=_non_empty_string(item.get("approver")),
        expiry=expiry,
        source_receipt_id=_non_empty_string(item.get("source_receipt_id")),
        bundle_hash=_non_empty_string(item.get("bundle_hash")),
        ack_status=ack_status,  # type: ignore[arg-type]
        last_used_at=_normalized_timestamp_string(item.get("last_used_at")),
        rejection_reason=_non_empty_string(item.get("rejection_reason")),
        provenance=resolved_provenance,  # type: ignore[arg-type]
    )


def _stored_cloud_exception_provenance(item: dict[str, object]) -> str:
    provenance = item.get("provenance")
    if provenance in {"receipt-sync", "policy-bundle"}:
        return str(provenance)
    if _non_empty_string(item.get("bundle_hash")) is not None:
        return "policy-bundle"
    return "receipt-sync"


def stored_receipt_sync_cloud_exceptions(items: list[dict[str, object]]) -> list[CloudException]:
    preserved = [
        item for item in items if isinstance(item, dict) and _stored_cloud_exception_provenance(item) == "receipt-sync"
    ]
    return build_cloud_exceptions_from_stored_items(preserved)


def build_cloud_exceptions_from_stored_items(items: list[dict[str, object]]) -> list[CloudException]:
    parsed: list[CloudException] = []
    for raw_item in items:
        item = cloud_exception_from_stored_dict(raw_item)
        if item is not None:
            parsed.append(item)
    return parsed


def build_cloud_exceptions_from_sync_payload(
    exceptions: list[dict[str, object]],
    *,
    bundle_hash: str | None = None,
    ack_status: str | None = None,
) -> list[CloudException]:
    items: list[CloudException] = []
    for raw_item in exceptions:
        parsed = cloud_exception_from_mapping(
            raw_item,
            bundle_hash=bundle_hash,
            ack_status=ack_status,
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
    return [item for item in active if item.harness in {harness, "*"}]


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
