"""Browser-assisted Guard connect helpers."""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import uuid
from datetime import datetime, timezone
from pathlib import Path

from ..daemon import ensure_guard_daemon, load_guard_surface_daemon_client
from ..daemon.client import GuardDaemonRequestError, GuardDaemonTransportError, GuardSurfaceDaemonClient
from ..runtime import sync_receipts, sync_runtime_session
from ..store import GuardStore

DEFAULT_GUARD_SYNC_URL = "https://hol.org/api/guard/receipts/sync"
DEFAULT_GUARD_CONNECT_URL = "https://hol.org/guard/connect"


def run_guard_connect_command(
    *,
    guard_home: Path,
    store: GuardStore,
    sync_url: str,
    connect_url: str,
    opener,
    wait_timeout_seconds: int,
) -> dict[str, object]:
    ensure_guard_daemon(guard_home)
    daemon_client = load_guard_surface_daemon_client(guard_home)
    normalized_connect_url, allowed_origin = resolve_connect_url(connect_url)
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
    except (RuntimeError, OSError, urllib.error.URLError, json.JSONDecodeError) as error:
        sync_message = str(error)
        if runtime_sync_error and not _is_paid_plan_sync_error(sync_message):
            sync_message = runtime_sync_error
        pending_sync_payload = dict(runtime_sync_summary)
        pending_sync_payload["synced_at"] = None
        pending_state = _record_connect_result(
            daemon_client=daemon_client,
            store=store,
            request_id=str(connect_request["request_id"]),
            status="connected",
            milestone="first_sync_pending",
            reason=sync_message,
            sync=pending_sync_payload,
        )
        return build_connect_payload(
            state=pending_state,
            browser_opened=browser_opened,
            connect_url=browser_url,
            sync_url=sync_url,
            connected=True,
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
        if not isinstance(state, dict):
            raise GuardDaemonRequestError("Guard daemon request failed: invalid connect state response")
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
        "browser_opened": browser_opened,
        "connect_url": connect_url,
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
    return payload


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
        except (GuardDaemonRequestError, GuardDaemonTransportError):
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
