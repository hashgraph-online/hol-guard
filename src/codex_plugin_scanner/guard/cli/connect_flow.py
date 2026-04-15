"""Browser-assisted Guard connect helpers."""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
from pathlib import Path

from ..daemon import ensure_guard_daemon, load_guard_surface_daemon_client
from ..runtime import sync_receipts
from ..store import GuardStore

DEFAULT_GUARD_SYNC_URL = "https://hol.org/api/guard/receipts/sync"
DEFAULT_GUARD_CONNECT_URL = "https://hol.org/guard/connect"
_PLAN_LIMITED_SYNC_PHRASES = (
    "paid guard plan",
    "guard plan required",
    "guard plan upgrade",
)


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
        sync_message = str(error)
        if _is_plan_limited_sync_error(sync_message):
            return {
                "connected": True,
                "browser_opened": browser_opened,
                "connect_url": browser_url,
                "sync_url": sync_url,
                "status": "paired_without_cloud_sync",
                "request_id": str(completion["request_id"]),
                "completed_at": completion.get("completed_at"),
                "sync_message": sync_message,
            }
        raise RuntimeError(f"Guard paired successfully but sync failed: {sync_message}") from error
    except (OSError, json.JSONDecodeError, urllib.error.URLError) as error:
        raise RuntimeError(f"Guard paired successfully but sync failed: {error}") from error
    return {
        "connected": True,
        "browser_opened": browser_opened,
        "connect_url": browser_url,
        "sync_url": sync_url,
        "status": str(completion["status"]),
        "request_id": str(completion["request_id"]),
        "completed_at": completion.get("completed_at"),
        "sync": sync_payload,
    }


def resolve_connect_url(connect_url: str) -> tuple[str, str]:
    parsed = urllib.parse.urlparse(connect_url.strip() or DEFAULT_GUARD_CONNECT_URL)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("Guard connect URL must be an absolute http(s) URL.")
    path = parsed.path or "/guard/connect"
    normalized_url = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, path, parsed.query, ""))
    allowed_origin = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))
    return normalized_url, allowed_origin


def _is_plan_limited_sync_error(message: str) -> bool:
    """Match the stable plan-limit phrases returned by Guard Cloud sync today."""

    normalized = message.strip().lower()
    has_plan_limit_phrase = any(phrase in normalized for phrase in _PLAN_LIMITED_SYNC_PHRASES)
    if "guard" in normalized and has_plan_limit_phrase:
        return True
    return "guard" in normalized and "sync" in normalized and "guard plan" in normalized and "upgrade" in normalized


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
