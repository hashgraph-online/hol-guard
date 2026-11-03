"""Canonical Cloud Review event delivery."""

from __future__ import annotations

import json
import urllib.parse
from typing import cast

CLOUD_REVIEW_EVENT_PROTOCOL_VERSION = 2
_EVENTS_PATH = "/api/guard/review/v2/events:batch"


class CloudReviewEventProtocolError(RuntimeError):
    """Cloud and daemon could not agree on the Review event protocol."""


def _resolve_sync_url(auth_context: dict[str, object], path: str) -> str:
    sync_url = str(auth_context.get("sync_url") or "")
    if not sync_url:
        raise RuntimeError("Guard sync URL is not configured.")
    parsed = urllib.parse.urlsplit(sync_url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise RuntimeError("Guard sync URL must be an absolute HTTP(S) URL.")
    normalized_path = path if path.startswith("/") else f"/{path}"
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, normalized_path, parsed.query, ""))


def _post_json(
    auth_context: dict[str, object],
    *,
    path: str,
    payload: dict[str, object],
) -> dict[str, object]:
    from .runner import _guard_sync_request, _urlopen_json_with_timeout_retry

    request = _guard_sync_request(
        auth_context,
        request_url=_resolve_sync_url(auth_context, path),
        method="POST",
        data=json.dumps(payload, separators=(",", ":")).encode("utf-8"),
    )
    return _urlopen_json_with_timeout_retry(
        request=request,
        timeout_seconds=35,
        retry_timeout_seconds=60,
    )


def post_review_events(
    auth_context: dict[str, object],
    *,
    events: list[dict[str, object]],
) -> dict[str, object]:
    sequences = [_positive_sequence(event) for event in events]
    response = _post_json(
        auth_context,
        path=_EVENTS_PATH,
        payload=_review_events_payload(events),
    )
    return _normalize_response(response, events=events, sequences=sequences)


def encoded_review_events_payload(events: list[dict[str, object]]) -> bytes:
    """Encode exactly the request body used by the Cloud Review endpoint."""
    return json.dumps(_review_events_payload(events), separators=(",", ":")).encode("utf-8")


def _review_events_payload(events: list[dict[str, object]]) -> dict[str, object]:
    sequences = [_positive_sequence(event) for event in events]
    if not sequences:
        raise CloudReviewEventProtocolError("A Review event batch cannot be empty.")
    return {
        "protocolVersion": CLOUD_REVIEW_EVENT_PROTOCOL_VERSION,
        "firstSequence": sequences[0],
        "lastSequence": sequences[-1],
        "events": events,
    }


def _positive_sequence(event: dict[str, object]) -> int:
    value = event.get("localStreamSequence")
    if type(value) is not int or value <= 0:
        raise CloudReviewEventProtocolError(
            "A Review event has no valid source sequence. Repair local Review data before retrying sync."
        )
    return value


def _normalize_response(
    response: dict[str, object],
    *,
    events: list[dict[str, object]],
    sequences: list[int],
) -> dict[str, object]:
    """Check Cloud's acknowledgement of one batch in the native ``cloud_review_ack`` kind."""

    from ..native_runner_authority import NativeRunnerAuthorityError, native_runner_authority

    request = {
        "response": response,
        "event_ids": [event.get("eventId") for event in events],
        "sequences": sequences,
    }
    try:
        answer = native_runner_authority("cloud_review_ack", request)
    except NativeRunnerAuthorityError as error:
        raise CloudReviewEventProtocolError(
            "Guard Cloud Review acknowledgement could not be checked without the HOL Guard native runtime."
        ) from error
    message = answer.get("error")
    if isinstance(message, str):
        raise CloudReviewEventProtocolError(message)
    normalized = answer.get("response")
    if not isinstance(normalized, dict):
        raise CloudReviewEventProtocolError("HOL Guard native runtime returned a malformed Review acknowledgement.")
    return cast("dict[str, object]", normalized)


__all__ = [
    "CLOUD_REVIEW_EVENT_PROTOCOL_VERSION",
    "CloudReviewEventProtocolError",
    "encoded_review_events_payload",
    "post_review_events",
]
