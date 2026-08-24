"""Canonical Cloud projection for immutable local Review outbox events."""

from __future__ import annotations

from datetime import datetime, timezone

from ..continuation_runtime import continuation_offer_payload
from ..review_contracts import (
    GuardReviewContractError,
    GuardReviewOAuthMetadata,
    build_local_review_request_claim,  # pyright: ignore[reportUnknownVariableType]
)
from ..store import GuardStore
from ..store_review_event_outbox_schema import REVIEW_EVENT_SCHEMA_VERSION
from .live_request_display import build_display_command, resolve_display_provenance
from .local_request_snapshots import (
    _cloud_safe_local_request_payload,  # pyright: ignore[reportPrivateUsage]
)
from .review_event_delivery import StoredReviewEventError, decode_stored_review_event

_EVENT_TYPE_MAP = {
    "pending": "request_created",
    "resolved": "request_resolved",
    "superseded": "request_superseded",
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _build_live_request_event(
    item: dict[str, object],
    *,
    oauth: GuardReviewOAuthMetadata | None,
    redaction_level: str,
    store: GuardStore,
    event_sequence: int,
) -> dict[str, object] | None:
    request_id = item.get("request_id")
    if not isinstance(request_id, str) or not request_id:
        return None
    stored_status = str(item.get("status") or "pending")
    status = "pending" if stored_status == "expired" else stored_status
    claim: dict[str, object] | None = None
    if oauth is not None:
        try:
            claim = build_local_review_request_claim(request_row=item, oauth=oauth, store=store)
        except GuardReviewContractError:
            claim = None
    display_command, display_summary, raw_command, redacted_command = build_display_command(item, redaction_level)
    request_payload = _cloud_safe_local_request_payload(item, redaction_level=redaction_level)
    continuation = continuation_offer_payload(store, request_row=item, now=_now(), headless=True)
    created_at = str(item.get("created_at") or _now())
    last_seen_at = str(item.get("last_seen_at") or created_at)
    return {
        "localRequestId": request_id,
        "correlationId": continuation["correlationId"],
        "localEventSequence": event_sequence,
        "eventType": _EVENT_TYPE_MAP.get(status, "request_created"),
        "harnessId": str(item.get("harness") or "guard-review"),
        "requestKind": str(item.get("review_kind") or item.get("harness") or "guard-review"),
        "displayProvenance": resolve_display_provenance(
            has_command_details=bool(request_payload.get("command_text")),
            redaction_level=redaction_level,
        ),
        "displayCommand": display_command,
        "displaySummary": display_summary,
        "rawCommand": raw_command,
        "redactedCommand": redacted_command,
        "reviewClaim": claim,
        "requestPayload": request_payload,
        "continuationCapability": continuation["capability"],
        "continuationHookAttached": continuation["hookAttached"],
        "continuationOpaqueTargetId": continuation["opaqueTargetId"],
        "continuationWaitDeadline": continuation["waitDeadline"],
        "riskCategory": str(item.get("risk_category") or "") or None,
        "policyAction": str(item.get("policy_action") or "") or None,
        "recommendedScope": str(item.get("recommended_scope") or "") or None,
        "localCreatedAt": created_at,
        "localUpdatedAt": str(item.get("updated_at") or last_seen_at),
        "localLastSeenAt": last_seen_at,
        "guardVersion": str(item.get("guard_version") or "") or None,
        "firstSeenGuardVersion": str(item.get("first_seen_guard_version") or "") or None,
        "lastSeenGuardVersion": str(item.get("last_seen_guard_version") or "") or None,
        "localEmittedAt": _now(),
        "sentAt": _now(),
    }


def project_live_request_outbox_row(
    store: GuardStore,
    *,
    outbox_row: dict[str, object],
    delivery_binding: dict[str, str],
    redaction_level: str,
    oauth: GuardReviewOAuthMetadata | None,
) -> tuple[int, dict[str, object]] | None:
    sequence = outbox_row.get("sequence")
    if not isinstance(sequence, int):
        raise RuntimeError("Live-request outbox sequence is invalid.")
    row_binding = {
        key: outbox_row.get(key)
        for key in ("oauth_subject_hash", "workspace_id", "machine_id", "machine_installation_id")
    }
    try:
        if row_binding != delivery_binding:
            raise StoredReviewEventError(
                "delivery_identity_mismatch",
                "Stored Review event identity does not match the active delivery binding.",
            )
        stored_event = decode_stored_review_event(outbox_row)
        event = _build_live_request_event(
            stored_event.snapshot,
            redaction_level=redaction_level,
            oauth=oauth,
            store=store,
            event_sequence=stored_event.request_sequence,
        )
        if event is None:
            raise StoredReviewEventError(
                "payload_snapshot_invalid",
                "Stored Review event snapshot has no local request identifier.",
            )
    except StoredReviewEventError as error:
        _ = store.quarantine_live_request_outbox_event(
            sequence,
            reason=error.reason,
            error=str(error),
            **delivery_binding,
        )
        return None
    event.update(
        {
            "eventId": stored_event.event_id,
            "eventSchemaVersion": REVIEW_EVENT_SCHEMA_VERSION,
            "eventType": stored_event.wire_event_type,
            "eventPayloadJson": stored_event.payload_json,
            "localEventSequence": stored_event.request_sequence,
            "localStreamSequence": stored_event.stream_sequence,
            "payloadHash": stored_event.payload_hash,
        }
    )
    return sequence, event
