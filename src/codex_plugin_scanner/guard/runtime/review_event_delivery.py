"""Validation and projection of immutable Review outbox events."""

from __future__ import annotations

from dataclasses import dataclass
from typing import cast

_ROW_COLUMNS = (
    "event_schema_version",
    "payload_json",
    "payload_hash",
    "oauth_source",
    "oauth_subject_hash",
    "workspace_id",
    "machine_id",
    "machine_installation_id",
    "event_type",
    "local_request_id",
    "stream_sequence",
    "request_sequence",
    "event_id",
)
_NATIVE_UNAVAILABLE_REASON = "cloud_native_projection_unavailable"


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
    native_replay: bool | None
    payload_hash: str
    payload_json: str
    request_sequence: int
    snapshot: dict[str, object]
    stream_sequence: int
    wire_event_type: str


def decode_stored_review_event(row: dict[str, object]) -> StoredReviewEvent:
    """Authenticate one stored event natively and return its immutable request snapshot."""

    from ..native_runner_authority import NativeRunnerAuthorityError, native_runner_authority

    try:
        answer = native_runner_authority("review_event_decode", {"row": {key: row.get(key) for key in _ROW_COLUMNS}})
    except NativeRunnerAuthorityError as error:
        # An outage retries the row instead of quarantining it.
        raise StoredReviewEventError(
            _NATIVE_UNAVAILABLE_REASON,
            "Native Review event decoding is unavailable; the Review event will be retried.",
        ) from error
    event = answer.get("event")
    if not isinstance(event, dict):
        raise StoredReviewEventError(str(answer.get("reason")), str(answer.get("message")))
    decoded = cast("dict[str, object]", event)
    continuation_result = decoded["continuation_result"]
    native_replay = decoded["native_replay"]
    return StoredReviewEvent(
        continuation_result=cast("dict[str, object]", continuation_result)
        if isinstance(continuation_result, dict)
        else None,
        event_id=str(decoded["event_id"]),
        event_type=str(decoded["event_type"]),
        native_replay=native_replay if isinstance(native_replay, bool) else None,
        payload_hash=str(row["payload_hash"]),
        payload_json=str(row["payload_json"]),
        request_sequence=cast(int, decoded["request_sequence"]),
        snapshot=cast("dict[str, object]", decoded["snapshot"]),
        stream_sequence=cast(int, decoded["stream_sequence"]),
        wire_event_type=str(decoded["wire_event_type"]),
    )
