"""Canonical Cloud Review event delivery."""

from __future__ import annotations

import json
import urllib.parse

CLOUD_REVIEW_EVENT_PROTOCOL_VERSION = 2
_EVENTS_PATH = "/api/guard/review/v2/events:batch"
_SUCCESS_STATUSES = frozenset({"accepted", "duplicate", "stale"})


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
    version = response.get("protocolVersion")
    if version != CLOUD_REVIEW_EVENT_PROTOCOL_VERSION:
        rendered = "missing" if version is None else str(version)
        raise CloudReviewEventProtocolError(
            f"Guard Cloud Review returned unsupported protocol version {rendered}. "
            "Update HOL Guard and reconnect Guard Cloud before retrying."
        )
    results = response.get("results")
    acknowledged_through = response.get("acknowledgedThrough")
    if not isinstance(results, list) or len(results) != len(events) or type(acknowledged_through) is not int:
        raise CloudReviewEventProtocolError(
            "Guard Cloud Review returned an invalid protocol 2 acknowledgement. Update HOL Guard before retrying."
        )
    normalized: list[dict[str, object]] = []
    for index, item in enumerate(results):
        expected_event_id = events[index].get("eventId")
        if not isinstance(item, dict) or item.get("eventId") != expected_event_id:
            raise CloudReviewEventProtocolError(
                "Guard Cloud Review returned an acknowledgement for a different event. Retry after updating HOL Guard."
            )
        status = item.get("status")
        if status not in {"accepted", "duplicate", "stale", "quarantined", "rejected"}:
            raise CloudReviewEventProtocolError(
                "Guard Cloud Review returned an unsupported event status. Update HOL Guard before retrying."
            )
        accepted = status in _SUCCESS_STATUSES
        if accepted and sequences[index] > acknowledged_through:
            raise CloudReviewEventProtocolError(
                "Guard Cloud Review acknowledgement stopped before an accepted event. "
                "Retry sync after updating HOL Guard."
            )
        normalized.append(
            {
                "index": index,
                "accepted": accepted,
                "code": item.get("code"),
                "error": None if accepted else (item.get("code") or status),
            }
        )
    accepted_count = sum(bool(item["accepted"]) for item in normalized)
    if response.get("accepted") != accepted_count or response.get("rejected") != len(events) - accepted_count:
        raise CloudReviewEventProtocolError(
            "Guard Cloud Review acknowledgement counts are inconsistent. Retry after updating HOL Guard."
        )
    normalized_response: dict[str, object] = {
        "accepted": accepted_count,
        "rejected": len(events) - accepted_count,
        "perEventResults": normalized,
        "acknowledgedThrough": acknowledged_through,
        "protocolVersion": CLOUD_REVIEW_EVENT_PROTOCOL_VERSION,
    }
    for field in ("maxBatchEvents", "maxBatchBytes"):
        value = response.get(field)
        if value is None:
            continue
        if type(value) is not int or value <= 0:
            raise CloudReviewEventProtocolError(
                "Guard Cloud Review returned an invalid batch limit. Update HOL Guard before retrying."
            )
        normalized_response[field] = value
    return normalized_response


__all__ = [
    "CLOUD_REVIEW_EVENT_PROTOCOL_VERSION",
    "CloudReviewEventProtocolError",
    "encoded_review_events_payload",
    "post_review_events",
]
