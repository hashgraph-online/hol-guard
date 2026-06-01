"""OAuth Device Code Guard connect helpers."""

from __future__ import annotations

import json
import urllib.parse
import urllib.request
from datetime import datetime, timezone

from ..store import GuardStore
from .oauth_client import resolve_guard_oauth_client_config

DEFAULT_GUARD_SYNC_URL = "https://hol.org/api/guard/receipts/sync"
DEFAULT_GUARD_CONNECT_URL = "https://hol.org/guard/connect"
DEFAULT_GUARD_DEVICE_SCOPES = (
    "guard:runtime.sync",
    "guard:receipt.write",
    "guard:runtime.session.write",
    "guard:offline_access",
)
CONNECT_COMMAND = "hol-guard connect"
CONNECT_STATUS_COMMAND = "hol-guard connect status"
CONNECT_REPAIR_COMMAND = "hol-guard connect repair"


def resolve_connect_url(connect_url: str) -> tuple[str, str]:
    parsed = urllib.parse.urlparse(connect_url.strip() or DEFAULT_GUARD_CONNECT_URL)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("Guard connect URL must be an absolute http(s) URL.")
    path = parsed.path or "/guard/connect"
    normalized_url = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, path, parsed.query, ""))
    allowed_origin = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))
    return normalized_url, allowed_origin


def build_device_authorization_request_body(
    *,
    machine_id: str,
    machine_label: str,
    runtime_id: str,
    runtime_label: str,
    client_id: str,
    scopes: tuple[str, ...] = DEFAULT_GUARD_DEVICE_SCOPES,
) -> str:
    return urllib.parse.urlencode(
        {
            "client_id": client_id,
            "scope": " ".join(scopes),
            "requested_machine_id": machine_id,
            "requested_machine_label": machine_label,
            "requested_runtime_id": runtime_id,
            "requested_runtime_label": runtime_label,
        }
    )


def build_device_authorization_copy_payload(response: dict[str, object]) -> dict[str, object]:
    user_code = str(response.get("user_code") or "").strip()
    verification_uri = str(response.get("verification_uri") or "").strip()
    verification_uri_complete = str(response.get("verification_uri_complete") or "").strip()
    if not user_code or not verification_uri:
        raise ValueError("Device authorization response is missing approval instructions.")
    next_target = verification_uri_complete or verification_uri
    return {
        "status": "waiting_for_approval",
        "user_code": user_code,
        "verification_uri": verification_uri,
        "verification_uri_complete": verification_uri_complete or None,
        "expires_in": int(response.get("expires_in") or 0),
        "interval": int(response.get("interval") or 5),
        "next_action": {
            "command": "open",
            "target": next_target,
            "message": f"Open {next_target} and enter code {user_code}.",
        },
    }


def device_authorization_endpoint_from_connect_url(connect_url: str) -> str:
    _, allowed_origin = resolve_connect_url(connect_url)
    return resolve_guard_oauth_client_config(allowed_origin).device_authorization_endpoint


def request_device_authorization(url: str, body: str) -> dict[str, object]:
    encoded_body = body.encode("utf-8")
    request = urllib.request.Request(
        url,
        data=encoded_body,
        method="POST",
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
        },
    )
    with urllib.request.urlopen(request, timeout=20) as response:
        payload = json.loads(response.read().decode("utf-8"))
    if not isinstance(payload, dict):
        raise RuntimeError("Guard Device Code authorization failed: invalid response.")
    return payload


def run_guard_device_connect_command(
    *,
    store: GuardStore,
    connect_url: str,
    request_device_authorization=request_device_authorization,
) -> dict[str, object]:
    device = store.get_device_metadata()
    _, allowed_origin = resolve_connect_url(connect_url)
    oauth_client = resolve_guard_oauth_client_config(allowed_origin)
    request_body = build_device_authorization_request_body(
        machine_id=str(device["installation_id"]),
        machine_label=str(device["device_label"]),
        runtime_id="hol-guard",
        runtime_label="HOL Guard CLI",
        client_id=oauth_client.client_id,
    )
    response = request_device_authorization(
        oauth_client.device_authorization_endpoint,
        request_body,
    )
    payload = build_device_authorization_copy_payload(response)
    payload["connect_mode"] = "device_code"
    return payload


def build_connect_status_payload(
    *,
    store: GuardStore,
    sync_url: str,
    connect_url: str,
    action: str = "status",
) -> dict[str, object]:
    latest_state = store.get_latest_guard_connect_state(now=datetime.now(timezone.utc).isoformat())
    status = str(latest_state.get("status") or "not_paired") if latest_state is not None else "not_paired"
    milestone = str(latest_state.get("milestone") or "not_started") if latest_state is not None else "not_started"
    reason = latest_state.get("reason") if latest_state is not None else None
    stored_sync_url = latest_state.get("sync_url") if latest_state is not None else None
    payload: dict[str, object] = {
        "status": status,
        "milestone": milestone,
        "reason": reason,
        "latest_connect_state": latest_state,
        "sync_url": stored_sync_url if isinstance(stored_sync_url, str) and stored_sync_url.strip() else sync_url,
        "connect_url": connect_url,
        "connect_command": CONNECT_COMMAND,
        "recovery_command": connect_recovery_command(latest_state),
        "connect_status_command": CONNECT_STATUS_COMMAND,
        "connect_repair_command": CONNECT_REPAIR_COMMAND,
    }
    if action in {"repair", "re-pair"}:
        payload["repair_action"] = "rerun_connect"
        payload["repair_message"] = "Run hol-guard connect to start OAuth Device Code approval."
    return payload


def connect_recovery_command(latest_state: dict[str, object] | None) -> str:
    if latest_state is None:
        return CONNECT_COMMAND
    milestone = str(latest_state.get("milestone") or "")
    status = str(latest_state.get("status") or "")
    if status in {"retry_required", "expired"} or milestone in {"first_sync_failed", "expired", "sync_not_available"}:
        return CONNECT_COMMAND
    if status == "connected" and milestone == "first_sync_succeeded":
        return "hol-guard sync"
    return CONNECT_COMMAND
