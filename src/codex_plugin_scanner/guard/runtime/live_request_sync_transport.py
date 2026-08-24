"""Versioned Cloud Review event delivery with an explicit legacy rollback path."""

from __future__ import annotations

import base64
import json
import os
import urllib.error
import urllib.parse

LIVE_REQUEST_SYNC_PROTOCOL_VERSION = "2"
V2_EVENTS_FLAG = "GUARD_CLOUD_REVIEW_V2_EVENTS_ENABLED"
LEGACY_EVENTS_FLAG = "GUARD_CLOUD_REVIEW_LEGACY_EVENTS_ENABLED"
_V2_EVENTS_PATH = "/api/guard/review/v2/events:batch"
_LEGACY_EVENTS_PATH = "/api/guard/live-requests/sync"
_SUCCESS_STATUSES = frozenset({"accepted", "duplicate", "stale"})


class LiveRequestSyncProtocolError(RuntimeError):
    """Cloud and daemon could not agree on the Review event protocol."""


def _flag_enabled(name: str, *, default: bool) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise RuntimeError(f"{name} must be enabled or disabled explicitly.")


def _resolve_sync_url(auth_context: dict[str, object], path: str) -> str:
    sync_url = str(auth_context.get("sync_url") or "")
    if not sync_url:
        raise RuntimeError("Guard sync URL is not configured.")
    parsed = urllib.parse.urlsplit(sync_url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise RuntimeError("Guard sync URL must be an absolute HTTP(S) URL.")
    normalized_path = path if path.startswith("/") else f"/{path}"
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, normalized_path, parsed.query, ""))


def _encode_live_request_events(events: list[dict[str, object]]) -> str:
    event_json = json.dumps(events, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(event_json).decode("ascii")


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


def _post_v2_events(
    auth_context: dict[str, object],
    *,
    events: list[dict[str, object]],
) -> dict[str, object]:
    sequences = [_positive_sequence(event) for event in events]
    response = _post_json(
        auth_context,
        path=_V2_EVENTS_PATH,
        payload={
            "protocolVersion": 2,
            "firstSequence": sequences[0],
            "lastSequence": sequences[-1],
            "events": events,
        },
    )
    return _normalize_v2_response(response, events=events, sequences=sequences)


def _post_legacy_events(
    auth_context: dict[str, object],
    *,
    workspace_id: str,
    machine_id: str,
    machine_installation_id: str,
    cursor: str | None,
    events: list[dict[str, object]],
) -> dict[str, object]:
    return _post_json(
        auth_context,
        path=_LEGACY_EVENTS_PATH,
        payload={
            "protocolVersion": LIVE_REQUEST_SYNC_PROTOCOL_VERSION,
            "deviceId": machine_id,
            "workspaceId": workspace_id,
            "machineInstallationId": machine_installation_id,
            "inboundCursor": cursor,
            "eventsBase64Url": _encode_live_request_events(events),
        },
    )


def _post_sync_events(
    auth_context: dict[str, object],
    *,
    workspace_id: str,
    machine_id: str,
    machine_installation_id: str,
    cursor: str | None,
    events: list[dict[str, object]],
) -> dict[str, object]:
    """Deliver through enabled protocols; legacy remains authoritative during dual-write."""

    v2_enabled = _flag_enabled(V2_EVENTS_FLAG, default=False)
    legacy_enabled = _flag_enabled(LEGACY_EVENTS_FLAG, default=True)
    if not v2_enabled and not legacy_enabled:
        raise RuntimeError("Guard Cloud Review event delivery is disabled for every supported protocol.")

    v2_result: dict[str, object] | None = None
    if v2_enabled:
        try:
            v2_result = _post_v2_events(auth_context, events=events)
        except urllib.error.HTTPError as error:
            if error.code == 426:
                raise LiveRequestSyncProtocolError(
                    "Guard Cloud Review rejected protocol version 2. Update HOL Guard and reconnect Guard Cloud "
                    "before retrying."
                ) from error
            if not legacy_enabled or error.code not in {404, 405}:
                raise

    if legacy_enabled:
        legacy_result = _post_legacy_events(
            auth_context,
            workspace_id=workspace_id,
            machine_id=machine_id,
            machine_installation_id=machine_installation_id,
            cursor=cursor,
            events=events,
        )
        if v2_result is not None and v2_result.get("rejected") != 0:
            return v2_result
        return legacy_result
    if v2_result is None:
        raise RuntimeError("Guard Cloud Review v2 event delivery did not complete.")
    return v2_result


def _positive_sequence(event: dict[str, object]) -> int:
    value = event.get("localStreamSequence")
    if type(value) is not int or value <= 0:
        raise LiveRequestSyncProtocolError(
            "A Review event has no valid source sequence. Repair local Review data before retrying sync."
        )
    return value


def _normalize_v2_response(
    response: dict[str, object],
    *,
    events: list[dict[str, object]],
    sequences: list[int],
) -> dict[str, object]:
    version = response.get("protocolVersion")
    if version != 2:
        rendered = "missing" if version is None else str(version)
        raise LiveRequestSyncProtocolError(
            f"Guard Cloud Review returned unsupported protocol version {rendered}. "
            "Update HOL Guard and reconnect Guard Cloud before retrying."
        )
    results = response.get("results")
    acknowledged_through = response.get("acknowledgedThrough")
    if not isinstance(results, list) or len(results) != len(events) or type(acknowledged_through) is not int:
        raise LiveRequestSyncProtocolError(
            "Guard Cloud Review returned an invalid v2 acknowledgement. Update HOL Guard before retrying."
        )
    normalized: list[dict[str, object]] = []
    for index, item in enumerate(results):
        expected_event_id = events[index].get("eventId")
        if not isinstance(item, dict) or item.get("eventId") != expected_event_id:
            raise LiveRequestSyncProtocolError(
                "Guard Cloud Review returned an acknowledgement for a different event. Retry after updating HOL Guard."
            )
        status = item.get("status")
        if status not in {"accepted", "duplicate", "stale", "quarantined", "rejected"}:
            raise LiveRequestSyncProtocolError(
                "Guard Cloud Review returned an unsupported event status. Update HOL Guard before retrying."
            )
        accepted = status in _SUCCESS_STATUSES
        if accepted and sequences[index] > acknowledged_through:
            raise LiveRequestSyncProtocolError(
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
        raise LiveRequestSyncProtocolError(
            "Guard Cloud Review v2 acknowledgement counts are inconsistent. Retry after updating HOL Guard."
        )
    return {
        "accepted": accepted_count,
        "rejected": len(events) - accepted_count,
        "perEventResults": normalized,
        "acknowledgedThrough": acknowledged_through,
        "protocolVersion": 2,
    }


__all__ = [
    "LEGACY_EVENTS_FLAG",
    "LIVE_REQUEST_SYNC_PROTOCOL_VERSION",
    "V2_EVENTS_FLAG",
    "LiveRequestSyncProtocolError",
    "_encode_live_request_events",
    "_post_sync_events",
    "_resolve_sync_url",
]
