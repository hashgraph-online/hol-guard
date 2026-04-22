"""Browser-assisted Guard connect helpers."""

from __future__ import annotations

import time
import urllib.parse
from pathlib import Path

from ..daemon import (
    clear_guard_daemon_state,
    ensure_guard_daemon,
    load_guard_daemon_auth_token,
    load_guard_surface_daemon_client,
)
from ..runtime import sync_receipts
from ..store import GuardStore

DEFAULT_GUARD_SYNC_URL = "https://hol.org/registry/api/v1"
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
    daemon_url, daemon_client = _resolve_guard_connect_daemon(guard_home)
    normalized_connect_url, allowed_origin = resolve_connect_url(connect_url)
    connect_request = daemon_client.create_connect_request(
        sync_url=sync_url,
        allowed_origin=allowed_origin,
    )
    browser_url = build_guard_connect_browser_url(
        connect_url=normalized_connect_url,
        daemon_url=daemon_url,
        request_id=str(connect_request["request_id"]),
        pairing_secret=str(connect_request["pairing_secret"]),
    )
    browser_opened = bool(opener(browser_url))
    completion = wait_for_connect_completion(
        store=store,
        request_id=str(connect_request["request_id"]),
        timeout_seconds=wait_timeout_seconds,
    )
    if completion is None:
        return {
            "connected": False,
            "browser_opened": browser_opened,
            "connect_url": browser_url,
            "sync_url": sync_url,
            "status": "waiting_for_browser",
        }
    try:
        sync_payload = sync_receipts(store)
    except RuntimeError as error:
        store.record_guard_connect_result(
            request_id=str(completion["request_id"]),
            status="retry_required",
            milestone="first_sync_failed",
            now=_now(),
            reason=str(error),
        )
        return {
            "connected": False,
            "browser_opened": browser_opened,
            "connect_url": browser_url,
            "sync_url": sync_url,
            "status": "retry_required",
            "milestone": "first_sync_failed",
            "reason": str(error),
            "request_id": str(completion["request_id"]),
            "completed_at": completion.get("completed_at"),
        }
    store.record_guard_connect_result(
        request_id=str(completion["request_id"]),
        status="connected",
        milestone="first_sync_succeeded",
        now=_now(),
        sync_payload=sync_payload,
    )
    handoff = _resolve_connect_handoff(store, sync_payload)
    return {
        "connected": True,
        "browser_opened": browser_opened,
        "connect_url": browser_url,
        "sync_url": sync_url,
        "status": str(completion["status"]),
        "request_id": str(completion["request_id"]),
        "completed_at": completion.get("completed_at"),
        "sync": sync_payload,
        "headline_state": "connected",
        "next_destination": handoff["href"],
        "next_destination_label": handoff["label"],
    }


def resolve_connect_url(connect_url: str) -> tuple[str, str]:
    parsed = urllib.parse.urlparse(connect_url.strip() or DEFAULT_GUARD_CONNECT_URL)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("Guard connect URL must be an absolute http(s) URL.")
    path = parsed.path or "/guard/connect"
    normalized_url = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, path, "", ""))
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


def wait_for_connect_completion(
    *,
    store: GuardStore,
    request_id: str,
    timeout_seconds: int,
    poll_interval_seconds: float = 0.25,
) -> dict[str, object] | None:
    deadline = time.monotonic() + max(1, timeout_seconds)
    while time.monotonic() < deadline:
        request = store.get_guard_connect_request(request_id)
        if request is not None and str(request.get("status")) == "completed":
            return request
        time.sleep(poll_interval_seconds)
    return None


def _resolve_connect_handoff(
    store: GuardStore,
    sync_payload: dict[str, object],
) -> dict[str, str]:
    if store.count_approval_requests() > 0:
        return {"href": "https://hol.org/guard/inbox", "label": "Open Guard Inbox"}
    if int(sync_payload.get("receipts_stored") or 0) > 0:
        return {"href": "https://hol.org/guard/dashboard", "label": "Open Guard Home"}
    return {"href": "https://hol.org/guard/fleet", "label": "Open Guard Fleet"}


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime())


def _resolve_guard_connect_daemon(guard_home: Path):
    daemon_url = ensure_guard_daemon(guard_home)
    try:
        return daemon_url, load_guard_surface_daemon_client(guard_home)
    except RuntimeError as error:
        if load_guard_daemon_auth_token(guard_home) is not None:
            raise error
    clear_guard_daemon_state(guard_home)
    daemon_url = ensure_guard_daemon(guard_home)
    return daemon_url, load_guard_surface_daemon_client(guard_home)
