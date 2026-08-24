"""Canonical Cloud projection for immutable local Review outbox events."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import cast

from ..review_contracts import (
    GuardReviewContractError,
    GuardReviewOAuthMetadata,
    build_local_review_request_claim,  # pyright: ignore[reportUnknownVariableType]
)
from ..store import GuardStore
from ..store_review_event_outbox_schema import REVIEW_EVENT_SCHEMA_VERSION
from .local_request_snapshots import (
    _cloud_safe_local_request_payload,  # pyright: ignore[reportPrivateUsage]
    _cloud_scrub_text,  # pyright: ignore[reportPrivateUsage]
    _local_request_command_text,  # pyright: ignore[reportPrivateUsage]
)
from .review_event_delivery import StoredReviewEventError, decode_stored_review_event

_COMMAND_MAX_UTF16_UNITS = 65_536
_SUMMARY_MAX_UTF16_UNITS = 512
_EVENT_TYPE_MAP = {
    "pending": "request_created",
    "resolved": "request_resolved",
    "superseded": "request_superseded",
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _display_provenance(*, has_command_details: bool, redaction_level: str) -> str:
    if redaction_level == "none":
        return "raw"
    if redaction_level == "full" and not has_command_details:
        return "withheld"
    return "redacted"


def _utf16_units(value: str) -> int:
    return sum(2 if ord(character) > 0xFFFF else 1 for character in value)


def _take_utf16_prefix(value: str, max_units: int) -> str:
    units = 0
    for index, character in enumerate(value):
        units += 2 if ord(character) > 0xFFFF else 1
        if units > max_units:
            return value[:index]
    return value


def _take_utf16_suffix(value: str, max_units: int) -> str:
    units = 0
    for index in range(len(value) - 1, -1, -1):
        units += 2 if ord(value[index]) > 0xFFFF else 1
        if units > max_units:
            return value[index + 1 :]
    return value


def _truncate_utf16(value: str, max_units: int) -> str:
    if _utf16_units(value) <= max_units:
        return value
    marker = " … [truncated] … "
    available_units = max_units - _utf16_units(marker)
    prefix_units = available_units * 3 // 4
    return (
        _take_utf16_prefix(value, prefix_units)
        + marker
        + _take_utf16_suffix(
            value,
            available_units - prefix_units,
        )
    )


def _build_display_command(item: dict[str, object], redaction_level: str) -> tuple[str, str, str | None, str | None]:
    action_identity = str(item.get("action_identity") or item.get("artifact_id") or "unknown")
    trigger_summary = str(item.get("trigger_summary") or item.get("why_now") or "Guard approval request")
    risk_headline = str(item.get("risk_headline") or item.get("risk_summary") or "")
    harness = str(item.get("harness") or "guard-review")
    fallback_display = f"{_cloud_scrub_text(harness)}: {_cloud_scrub_text(action_identity)}"
    envelope_value = item.get("action_envelope_json")
    envelope = cast(dict[str, object], envelope_value) if isinstance(envelope_value, dict) else None
    command_text = _local_request_command_text(item, envelope)
    safe_command = _cloud_scrub_text(command_text) if command_text else None
    display_command = _truncate_utf16(safe_command or fallback_display, _COMMAND_MAX_UTF16_UNITS)
    display_summary = f"{risk_headline} — {trigger_summary}" if risk_headline else trigger_summary
    display_summary = _truncate_utf16(display_summary, _SUMMARY_MAX_UTF16_UNITS)
    raw_command = display_command if redaction_level == "none" and safe_command else None
    redacted_command = display_command if redaction_level != "none" and safe_command else None
    return display_command, display_summary, raw_command, redacted_command


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
    display_command, display_summary, raw_command, redacted_command = _build_display_command(item, redaction_level)
    request_payload = _cloud_safe_local_request_payload(item, redaction_level=redaction_level)
    created_at = str(item.get("created_at") or _now())
    last_seen_at = str(item.get("last_seen_at") or created_at)
    return {
        "localRequestId": request_id,
        "localEventSequence": event_sequence,
        "eventType": _EVENT_TYPE_MAP.get(status, "request_created"),
        "harnessId": str(item.get("harness") or "guard-review"),
        "requestKind": str(item.get("review_kind") or item.get("harness") or "guard-review"),
        "displayProvenance": _display_provenance(
            has_command_details=bool(request_payload.get("command_text")),
            redaction_level=redaction_level,
        ),
        "displayCommand": display_command,
        "displaySummary": display_summary,
        "rawCommand": raw_command,
        "redactedCommand": redacted_command,
        "reviewClaim": claim,
        "requestPayload": request_payload,
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
        _ = store.dead_letter_live_request_outbox_event(
            sequence,
            reason=error.reason,
            error=str(error),
            oauth_subject_hash=delivery_binding["oauth_subject_hash"],
            workspace_id=delivery_binding["workspace_id"],
            machine_id=delivery_binding["machine_id"],
            machine_installation_id=delivery_binding["machine_installation_id"],
            retain_outbox_event=True,
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
