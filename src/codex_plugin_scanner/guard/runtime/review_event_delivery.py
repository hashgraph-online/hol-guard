"""Validation and projection of immutable Review outbox events."""

from __future__ import annotations

import hmac
import json
from dataclasses import dataclass
from typing import cast

from ..review_event_integrity import review_event_payload_digest
from ..store_review_event_outbox_schema import (
    REVIEW_EVENT_SCHEMA_NAME,
    REVIEW_EVENT_SCHEMA_VERSION,
    REVIEW_REQUEST_SNAPSHOT_COLUMNS,
)

_WIRE_EVENT_TYPES = {
    "review.request.created": "request_created",
    "review.request.refreshed": "request_created",
    "review.request.resolved": "request_resolved",
    "review.request.snapshot_migrated": "request_created",
    "review.request.snapshot_requeued": "request_created",
    "review.continuation.resumed": "continuation_resumed",
    "review.continuation.already_resumed": "continuation_already_resumed",
    "review.continuation.manual_retry_required": "continuation_manual_retry_required",
    "review.continuation.blocked_not_resumed": "continuation_blocked_not_resumed",
    "review.continuation.unsupported": "continuation_unsupported",
    "review.continuation.failed": "continuation_failed",
}
_CONTINUATION_EVENT_TYPES = frozenset(
    event_type for event_type in _WIRE_EVENT_TYPES if event_type.startswith("review.continuation.")
)
_CONTINUATION_STATUSES = frozenset(
    event_type.removeprefix("review.continuation.") for event_type in _CONTINUATION_EVENT_TYPES
)
_SNAPSHOT_JSON_FIELDS = (
    "action_envelope_json",
    "browser_intent_json",
    "continuation_snapshot_json",
    "changed_fields_json",
    "decision_v2_json",
    "risk_signals_json",
    "scanner_evidence_json",
)
_REQUIRED_NONEMPTY_SNAPSHOT_FIELDS = (
    "request_id",
    "harness",
    "artifact_id",
    "artifact_name",
    "artifact_type",
    "artifact_hash",
    "policy_action",
    "recommended_scope",
    "changed_fields_json",
    "source_scope",
    "oauth_source",
    "config_path",
    "risk_signals_json",
    "scanner_evidence_json",
    "review_command",
    "approval_url",
    "status",
    "created_at",
)


class StoredReviewEventError(ValueError):
    """An outbox row cannot be authenticated or interpreted safely."""

    def __init__(self, reason: str, message: str) -> None:
        super().__init__(message)
        self.reason: str = reason


@dataclass(frozen=True)
class StoredReviewEvent:
    continuation_result: dict[str, object] | None
    event_id: str
    event_type: str
    payload: dict[str, object]
    payload_hash: str
    payload_json: str
    request_sequence: int
    snapshot: dict[str, object]
    stream_sequence: int

    @property
    def wire_event_type(self) -> str:
        return _WIRE_EVENT_TYPES[self.event_type]


def _object(value: object, *, reason: str, message: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise StoredReviewEventError(reason, message)
    raw = cast(dict[object, object], value)
    if any(not isinstance(key, str) for key in raw):
        raise StoredReviewEventError(reason, message)
    return cast(dict[str, object], raw)


def _decode_snapshot(payload: dict[str, object]) -> dict[str, object]:
    raw_snapshot = payload.get("requestSnapshot")
    if raw_snapshot is None:
        raise StoredReviewEventError(
            "payload_snapshot_missing",
            "Stored Review event has no immutable request snapshot.",
        )
    snapshot = _object(
        raw_snapshot,
        reason="payload_snapshot_invalid",
        message="Stored Review event request snapshot is invalid.",
    )
    expected = set(REVIEW_REQUEST_SNAPSHOT_COLUMNS)
    actual = set(snapshot)
    optional_legacy_fields = {"continuation_snapshot_json"}
    if missing := sorted(expected - actual - optional_legacy_fields):
        raise StoredReviewEventError(
            "payload_snapshot_incomplete",
            f"Stored Review event snapshot is missing canonical fields: {', '.join(missing)}.",
        )
    if unexpected := sorted(actual - expected):
        raise StoredReviewEventError(
            "payload_snapshot_unexpected_fields",
            f"Stored Review event snapshot has unexpected fields: {', '.join(unexpected)}.",
        )
    for field in optional_legacy_fields:
        snapshot.setdefault(field, None)
    invalid = [
        field
        for field in _REQUIRED_NONEMPTY_SNAPSHOT_FIELDS
        if not isinstance(snapshot[field], str) or not str(snapshot[field]).strip()
    ]
    if invalid:
        raise StoredReviewEventError(
            "payload_snapshot_incomplete",
            f"Stored Review event snapshot has invalid canonical fields: {', '.join(invalid)}.",
        )
    for field in _SNAPSHOT_JSON_FIELDS:
        value = snapshot.get(field)
        if not isinstance(value, str):
            continue
        try:
            snapshot[field] = json.loads(value)
        except json.JSONDecodeError as error:
            raise StoredReviewEventError(
                "payload_snapshot_invalid",
                f"Stored Review event snapshot field {field} is invalid JSON.",
            ) from error
    return snapshot


def _decode_continuation_result(payload: dict[str, object], *, event_type: str) -> dict[str, object] | None:
    raw_result = payload.get("continuationResult")
    if event_type not in _CONTINUATION_EVENT_TYPES:
        if raw_result is not None:
            raise StoredReviewEventError(
                "payload_continuation_unexpected",
                "Stored Review request event contains unexpected continuation evidence.",
            )
        return None
    result = _object(
        raw_result,
        reason="payload_continuation_missing",
        message="Stored Review continuation event has no terminal result.",
    )
    expected_fields = {
        "action",
        "capability",
        "completedAt",
        "correlationId",
        "evidenceId",
        "reason",
        "status",
    }
    if set(result) != expected_fields:
        raise StoredReviewEventError(
            "payload_continuation_invalid",
            "Stored Review continuation result fields are invalid.",
        )
    status = result.get("status")
    if status not in _CONTINUATION_STATUSES or event_type != f"review.continuation.{status}":
        raise StoredReviewEventError(
            "payload_continuation_invalid",
            "Stored Review continuation status does not match its event.",
        )
    if result.get("action") not in {"allow_once", "block"}:
        raise StoredReviewEventError("payload_continuation_invalid", "Stored Review continuation action is invalid.")
    if any(
        not isinstance(result.get(field), str) or not str(result[field]).strip()
        for field in expected_fields - {"action", "status"}
    ):
        raise StoredReviewEventError(
            "payload_continuation_invalid",
            "Stored Review continuation result is incomplete.",
        )
    return result


def decode_stored_review_event(row: dict[str, object]) -> StoredReviewEvent:
    """Authenticate one stored event and return its immutable request snapshot."""

    version = row.get("event_schema_version")
    if version != REVIEW_EVENT_SCHEMA_VERSION:
        raise StoredReviewEventError(
            "unsupported_event_schema",
            f"Unsupported Review event schema version: {version!r}.",
        )
    payload_json = row.get("payload_json")
    payload_hash = row.get("payload_hash")
    if not isinstance(payload_json, str) or not isinstance(payload_hash, str):
        raise StoredReviewEventError("payload_hash_mismatch", "Stored Review event payload metadata is invalid.")
    actual_hash = review_event_payload_digest(
        payload_json,
        oauth_source=row.get("oauth_source"),
        oauth_subject_hash=row.get("oauth_subject_hash"),
        workspace_id=row.get("workspace_id"),
        machine_id=row.get("machine_id"),
        machine_installation_id=row.get("machine_installation_id"),
    )
    if not hmac.compare_digest(actual_hash, payload_hash):
        raise StoredReviewEventError("payload_hash_mismatch", "Stored Review event payload integrity check failed.")
    try:
        payload = _object(
            cast(object, json.loads(payload_json)),
            reason="payload_json_invalid",
            message="Stored Review event payload is not an object.",
        )
    except json.JSONDecodeError as error:
        raise StoredReviewEventError("payload_json_invalid", "Stored Review event payload is invalid JSON.") from error

    event_type = row.get("event_type")
    local_request_id = row.get("local_request_id")
    oauth_source = row.get("oauth_source")
    if not isinstance(event_type, str) or event_type not in _WIRE_EVENT_TYPES:
        raise StoredReviewEventError("unsupported_event_type", f"Unsupported Review event type: {event_type!r}.")
    if (
        payload.get("schema") != REVIEW_EVENT_SCHEMA_NAME
        or payload.get("eventType") != event_type
        or payload.get("localRequestId") != local_request_id
    ):
        raise StoredReviewEventError(
            "payload_metadata_mismatch",
            "Stored Review event payload does not match its authenticated envelope.",
        )
    if payload.get("oauthSource") != oauth_source:
        raise StoredReviewEventError(
            "payload_source_binding_mismatch",
            "Stored Review event OAuth source does not match its delivery binding.",
        )
    snapshot = _decode_snapshot(payload)
    continuation_result = _decode_continuation_result(payload, event_type=event_type)
    if snapshot["request_id"] != local_request_id:
        raise StoredReviewEventError(
            "payload_snapshot_request_mismatch",
            "Stored Review event snapshot request does not match its authenticated envelope.",
        )
    if snapshot["oauth_source"] != payload.get("oauthSource"):
        raise StoredReviewEventError(
            "payload_snapshot_source_mismatch",
            "Stored Review event snapshot OAuth source does not match its authenticated envelope.",
        )
    stream_sequence = row.get("stream_sequence")
    request_sequence = row.get("request_sequence")
    event_id = row.get("event_id")
    if not isinstance(stream_sequence, int) or not isinstance(request_sequence, int) or not isinstance(event_id, str):
        raise StoredReviewEventError("payload_metadata_mismatch", "Stored Review event sequence metadata is invalid.")
    return StoredReviewEvent(
        continuation_result=continuation_result,
        event_id=event_id,
        event_type=event_type,
        payload=payload,
        payload_hash=payload_hash,
        payload_json=payload_json,
        request_sequence=request_sequence,
        snapshot=snapshot,
        stream_sequence=stream_sequence,
    )
