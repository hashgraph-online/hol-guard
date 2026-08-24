"""HTTP transport primitives for Guard Cloud Review event delivery."""

from __future__ import annotations

import base64
import json
import urllib.parse


def resolve_sync_url(auth_context: dict[str, object], path: str) -> str:
    sync_url = str(auth_context.get("sync_url") or "")
    if not sync_url:
        raise RuntimeError("Guard sync URL is not configured.")
    parsed = urllib.parse.urlsplit(sync_url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise RuntimeError("Guard sync URL must be an absolute HTTP(S) URL.")
    normalized_path = path if path.startswith("/") else f"/{path}"
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, normalized_path, parsed.query, ""))


def encode_live_request_events(events: list[dict[str, object]]) -> str:
    event_json = json.dumps(events, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(event_json).decode("ascii")


def post_sync_events(
    auth_context: dict[str, object],
    *,
    workspace_id: str,
    machine_id: str,
    machine_installation_id: str,
    cursor: str | None,
    events: list[dict[str, object]],
) -> dict[str, object]:
    from .runner import _guard_sync_request, _urlopen_json_with_timeout_retry

    request_url = resolve_sync_url(auth_context, "/api/guard/live-requests/sync")
    payload: dict[str, object] = {
        "protocolVersion": "2",
        "deviceId": machine_id,
        "workspaceId": workspace_id,
        "machineInstallationId": machine_installation_id,
        "inboundCursor": cursor,
        "eventsBase64Url": encode_live_request_events(events),
    }
    request = _guard_sync_request(
        auth_context,
        request_url=request_url,
        method="POST",
        data=json.dumps(payload, separators=(",", ":")).encode("utf-8"),
    )
    return _urlopen_json_with_timeout_retry(request=request, timeout_seconds=35, retry_timeout_seconds=60)
