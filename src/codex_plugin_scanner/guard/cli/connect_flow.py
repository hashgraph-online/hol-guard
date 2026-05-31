"""Browser-assisted Guard connect helpers."""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path

from ..daemon import ensure_guard_daemon, load_guard_surface_daemon_client
from ..daemon.client import GuardDaemonRequestError, GuardDaemonTransportError, GuardSurfaceDaemonClient
from ..daemon.manager import clear_guard_daemon_state
from ..runtime import GuardSyncNotAvailableError, sync_receipts, sync_runtime_session
from ..store import GuardStore

DEFAULT_GUARD_SYNC_URL = "https://hol.org/api/guard/receipts/sync"
DEFAULT_GUARD_CONNECT_URL = "https://hol.org/guard/connect"
DEFAULT_GUARD_DEVICE_CLIENT_ID = "guard-local-daemon"
DEFAULT_GUARD_DEVICE_SCOPES = (
    "guard:runtime.sync",
    "guard:receipt.write",
    "guard:runtime.session.write",
    "guard:offline_access",
)
CONNECT_COMMAND = "hol-guard connect"
CONNECT_STATUS_COMMAND = "hol-guard connect status"
CONNECT_REPAIR_COMMAND = "hol-guard connect repair"


def _load_connect_daemon_client(guard_home: Path) -> GuardSurfaceDaemonClient:
    try:
        return load_guard_surface_daemon_client(guard_home)
    except RuntimeError:
        clear_guard_daemon_state(guard_home)
        ensure_guard_daemon(guard_home)
        return load_guard_surface_daemon_client(guard_home)


def run_guard_connect_command(
    *,
    guard_home: Path,
    store: GuardStore,
    sync_url: str,
    connect_url: str,
    opener,
    wait_timeout_seconds: int,
) -> dict[str, object]:
    normalized_connect_url, allowed_origin = resolve_connect_url(connect_url)
    ensure_guard_daemon(guard_home)
    daemon_client = _load_connect_daemon_client(guard_home)
    connect_request = daemon_client.create_connect_request(
        sync_url=sync_url,
        allowed_origin=allowed_origin,
    )
    browser_url = build_guard_connect_browser_url(
        connect_url=normalized_connect_url,
        daemon_url=daemon_client.daemon_url,
        request_id=str(connect_request["request_id"]),
        pairing_secret=str(connect_request["pairing_secret"]),
    )
    browser_opened = bool(opener(browser_url))
    transition = wait_for_connect_transition(
        daemon_client=daemon_client,
        request_id=str(connect_request["request_id"]),
        timeout_seconds=wait_timeout_seconds,
    )
    if transition is None:
        return build_connect_payload(
            state={
                "request_id": str(connect_request["request_id"]),
                "status": "waiting",
                "milestone": "waiting_for_browser",
                "reason": "waiting_for_browser",
                "completed_at": None,
                "expires_at": connect_request.get("expires_at"),
                "proof": {},
            },
            browser_opened=browser_opened,
            connect_url=browser_url,
            sync_url=sync_url,
            connected=False,
        )
    if str(transition.get("status")) == "expired":
        return build_connect_payload(
            state=transition,
            browser_opened=browser_opened,
            connect_url=browser_url,
            sync_url=sync_url,
            connected=False,
        )
    pairing_completed_at = (transition.get("completed_at") or "").strip()
    if str(transition.get("status")) == "retry_required" and not pairing_completed_at:
        return build_connect_payload(
            state=transition,
            browser_opened=browser_opened,
            connect_url=browser_url,
            sync_url=sync_url,
            connected=False,
        )
    runtime_session = _start_guard_runtime_session(daemon_client)
    runtime_sync_error: str | None = None
    try:
        runtime_sync_summary = sync_runtime_session(store, session=runtime_session)
    except (RuntimeError, OSError, urllib.error.URLError, json.JSONDecodeError) as error:
        runtime_sync_error = str(error)
        runtime_sync_summary = {
            "runtime_session_id": str(runtime_session.get("session_id") or runtime_session.get("sessionId") or ""),
            "runtime_session_synced_at": None,
            "runtime_sessions_visible": 0,
            "runtime_session_sync_pending": True,
            "runtime_session_sync_reason": runtime_sync_error,
        }
    try:
        sync_payload = sync_receipts(store)
    except GuardSyncNotAvailableError as plan_error:
        plan_msg = str(plan_error).strip() or "Cloud sync requires a paid Guard plan."
        pending_sync_payload = dict(runtime_sync_summary)
        pending_sync_payload["synced_at"] = None
        return _build_sync_not_available_payload(
            daemon_client=daemon_client,
            store=store,
            request_id=str(connect_request["request_id"]),
            reason=plan_msg,
            sync=pending_sync_payload,
            browser_opened=browser_opened,
            connect_url=browser_url,
            sync_url=sync_url,
        )
    except (RuntimeError, OSError, urllib.error.URLError, json.JSONDecodeError) as error:
        sync_message = str(error)
        pending_sync_payload = dict(runtime_sync_summary)
        pending_sync_payload["synced_at"] = None
        if _is_paid_plan_sync_error(sync_message):
            return _build_sync_not_available_payload(
                daemon_client=daemon_client,
                store=store,
                request_id=str(connect_request["request_id"]),
                reason=sync_message,
                sync=pending_sync_payload,
                browser_opened=browser_opened,
                connect_url=browser_url,
                sync_url=sync_url,
            )
        pending_state = _record_connect_result(
            daemon_client=daemon_client,
            store=store,
            request_id=str(connect_request["request_id"]),
            status="retry_required",
            milestone="first_sync_failed",
            reason=sync_message,
            sync=pending_sync_payload,
        )
        return build_connect_payload(
            state=pending_state,
            browser_opened=browser_opened,
            connect_url=browser_url,
            sync_url=sync_url,
            connected=False,
            sync=pending_sync_payload,
            sync_message=sync_message,
        )
    sync_payload["runtime_session_synced_at"] = runtime_sync_summary["runtime_session_synced_at"]
    sync_payload["runtime_session_id"] = runtime_sync_summary["runtime_session_id"]
    sync_payload["runtime_sessions_visible"] = runtime_sync_summary["runtime_sessions_visible"]
    if runtime_sync_error is not None:
        sync_payload["runtime_session_sync_pending"] = True
        sync_payload["runtime_session_sync_reason"] = runtime_sync_error
        pending_sync_payload = dict(sync_payload)
        pending_sync_payload["synced_at"] = None
        pending_state = _record_connect_result(
            daemon_client=daemon_client,
            store=store,
            request_id=str(connect_request["request_id"]),
            status="connected",
            milestone="first_sync_pending",
            reason=runtime_sync_error,
            sync=pending_sync_payload,
        )
        return build_connect_payload(
            state=pending_state,
            browser_opened=browser_opened,
            connect_url=browser_url,
            sync_url=sync_url,
            connected=True,
            sync=pending_sync_payload,
            sync_message=runtime_sync_error,
        )
    final_state = _record_connect_result(
        daemon_client=daemon_client,
        store=store,
        request_id=str(connect_request["request_id"]),
        status="connected",
        milestone="first_sync_succeeded",
        sync=sync_payload,
    )
    return build_connect_payload(
        state=final_state,
        browser_opened=browser_opened,
        connect_url=browser_url,
        sync_url=sync_url,
        connected=True,
        sync=sync_payload,
        sync_available=True,
    )


def _is_paid_plan_sync_error(message: str) -> bool:
    normalized = message.strip().lower()
    return (
        "paid guard plan" in normalized
        or "paid plan" in normalized
        or "guard plan required" in normalized
        or "payment required" in normalized
        or "http error 402" in normalized
    )


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
    client_id: str = DEFAULT_GUARD_DEVICE_CLIENT_ID,
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
    return f"{allowed_origin}/api/guard/oauth/device/authorize"


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
    request_body = build_device_authorization_request_body(
        machine_id=str(device["installation_id"]),
        machine_label=str(device["device_label"]),
        runtime_id="hol-guard",
        runtime_label="HOL Guard CLI",
    )
    response = request_device_authorization(
        device_authorization_endpoint_from_connect_url(connect_url),
        request_body,
    )
    payload = build_device_authorization_copy_payload(response)
    payload["connect_mode"] = "device_code"
    return payload


def build_guard_connect_browser_url(
    *,
    connect_url: str,
    daemon_url: str,
    request_id: str,
    pairing_secret: str,
) -> str:
    parsed = urllib.parse.urlparse(connect_url)
    query_pairs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    query_pairs.extend(
        [
            ("guardPairRequest", request_id),
            ("guardDaemon", daemon_url),
        ]
    )
    fragment = urllib.parse.urlencode({"guardPairSecret": pairing_secret})
    return urllib.parse.urlunsplit(
        (
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            urllib.parse.urlencode(query_pairs),
            fragment,
        )
    )


def wait_for_connect_transition(
    *,
    daemon_client: GuardSurfaceDaemonClient,
    request_id: str,
    timeout_seconds: int,
    poll_interval_seconds: float = 0.25,
) -> dict[str, object] | None:
    deadline = time.monotonic() + max(1, timeout_seconds)
    while time.monotonic() < deadline:
        try:
            state = daemon_client.get_connect_state(request_id=request_id)
        except GuardDaemonTransportError:
            time.sleep(poll_interval_seconds)
            continue
        except GuardDaemonRequestError:
            raise
        if not isinstance(state, dict):
            raise RuntimeError("Guard daemon request failed: invalid connect state response")
        if str(state.get("status")) in {"connected", "retry_required", "expired"}:
            return state
        if str(state.get("milestone")) == "first_sync_pending":
            return state
        time.sleep(poll_interval_seconds)
    return None


def build_connect_payload(
    *,
    state: dict[str, object],
    browser_opened: bool,
    connect_url: str,
    sync_url: str,
    connected: bool,
    sync: dict[str, object] | None = None,
    sync_message: str | None = None,
    sync_available: bool | None = None,
) -> dict[str, object]:
    milestones = [
        {
            "label": "browser_opened",
            "status": "completed" if browser_opened else "pending",
        },
        {
            "label": "pairing_completed",
            "status": "completed" if state.get("completed_at") else "pending",
        },
        {
            "label": "first_sync",
            "status": _resolve_first_sync_milestone(state),
        },
    ]
    payload = {
        "connected": connected,
        "sync_available": sync_available if sync_available is not None else connected,
        "browser_opened": browser_opened,
        "connect_url": connect_url,
        "cloud_pairing_url": connect_url,
        "sync_url": sync_url,
        "status": str(state.get("status") or "waiting"),
        "milestone": str(state.get("milestone") or "waiting_for_browser"),
        "reason": state.get("reason"),
        "request_id": state.get("request_id"),
        "completed_at": state.get("completed_at"),
        "expires_at": state.get("expires_at"),
        "proof": dict(state.get("proof")) if isinstance(state.get("proof"), dict) else {},
        "milestones": milestones,
    }
    if sync is not None:
        payload["sync"] = sync
    if sync_message is not None and sync_message.strip():
        payload["sync_message"] = sync_message
    if not browser_opened:
        payload["next_action"] = {
            "label": "Copy pairing URL",
            "reason": "Browser did not open automatically.",
            "target": connect_url,
        }
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
        payload["repair_message"] = "Run hol-guard connect to create a fresh pairing request and first sync."
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


def _build_sync_not_available_payload(
    *,
    daemon_client: GuardSurfaceDaemonClient,
    store: GuardStore,
    request_id: str,
    reason: str,
    sync: dict[str, object],
    browser_opened: bool,
    connect_url: str,
    sync_url: str,
) -> dict[str, object]:
    message = "Local Guard is connected. Shared cloud sync needs a paid Guard plan."
    pending_state = _record_connect_result(
        daemon_client=daemon_client,
        store=store,
        request_id=request_id,
        status="connected",
        milestone="sync_not_available",
        reason=message,
        sync={**sync, "sync_not_available_reason": reason},
    )
    return build_connect_payload(
        state=pending_state,
        browser_opened=browser_opened,
        connect_url=connect_url,
        sync_url=sync_url,
        connected=True,
        sync={**sync, "sync_not_available_reason": reason},
        sync_available=False,
        sync_message=message,
    )


def _record_connect_result(
    *,
    daemon_client: GuardSurfaceDaemonClient,
    store: GuardStore,
    request_id: str,
    status: str,
    milestone: str,
    reason: str | None = None,
    sync: dict[str, object] | None = None,
) -> dict[str, object]:
    try:
        return daemon_client.report_connect_result(
            request_id=request_id,
            status=status,
            milestone=milestone,
            reason=reason,
            sync=sync,
        )
    except RuntimeError:
        return store.record_guard_connect_result(
            request_id=request_id,
            status=status,
            milestone=milestone,
            now=datetime.now(timezone.utc).isoformat(),
            reason=reason,
            sync_payload=sync,
        )


def _resolve_first_sync_milestone(state: dict[str, object]) -> str:
    milestone = str(state.get("milestone") or "")
    if milestone == "first_sync_succeeded":
        return "completed"
    if milestone == "first_sync_failed":
        return "failed"
    if milestone == "first_sync_pending":
        return "waiting"
    if milestone == "sync_not_available":
        return "skipped"
    return "pending"


def _start_guard_runtime_session(daemon_client: GuardSurfaceDaemonClient) -> dict[str, object]:
    start_session = getattr(daemon_client, "start_session", None)
    if callable(start_session):
        try:
            return start_session(
                harness="hol-guard",
                surface="cli",
                workspace=str(Path.cwd()),
                client_name="hol-guard",
                client_title="HOL Guard CLI",
                client_version=None,
                capabilities=["approval-resolution", "receipt-view", "runtime-sync"],
            )
        except RuntimeError:
            pass
    now = datetime.now(timezone.utc).isoformat()
    return {
        "session_id": f"guard-session-{uuid.uuid4().hex}",
        "harness": "hol-guard",
        "surface": "cli",
        "status": "active",
        "client_name": "hol-guard",
        "client_title": "HOL Guard CLI",
        "client_version": None,
        "workspace": str(Path.cwd()),
        "capabilities": ["approval-resolution", "receipt-view", "runtime-sync"],
        "operations": [],
        "created_at": now,
        "updated_at": now,
    }
