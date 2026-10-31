"""User-facing approval links for live harness hook output."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from urllib.parse import urlparse

from .daemon.auth_token import load_guard_daemon_auth_token
from .local_dashboard_session import build_approval_browser_url

_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1", "localhost"})
_SIGNED_APPROVAL_LINK_UNAVAILABLE = (
    "HOL Guard could not create a signed approval link; open Inbox from Guard on this device, then retry."
)


def approval_review_url_from_payload(payload: Mapping[str, object]) -> str | None:
    """Return the local approval-center URL the harness should open, if one exists."""

    for key in ("primary_approval_url", "approval_url", "guardApprovalUrl"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    queued = payload.get("approval_requests")
    if not isinstance(queued, list):
        return None
    for item in queued:
        if not isinstance(item, Mapping):
            continue
        value = item.get("approval_url")
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def live_approval_review_url(url: str, *, guard_home: Path | None) -> str:
    """Attach a loopback dashboard session fragment so the link opens signed-in."""

    if not url or guard_home is None or not is_loopback_approval_url(url):
        return url
    token = load_guard_daemon_auth_token(guard_home)
    tokenized = build_approval_browser_url(url, auth_token=token)
    return tokenized if tokenized else url


def authenticated_approval_review_url(
    url: str,
    *,
    guard_home: Path | None,
    surface: str = "approval-center",
) -> str | None:
    """Return a signed loopback link, an unchanged external link, or no safe local link."""

    if not url or not is_loopback_approval_url(url):
        return url
    if guard_home is None:
        return None
    try:
        token = load_guard_daemon_auth_token(guard_home)
        if not token:
            return None
        return build_approval_browser_url(url, auth_token=token, surface=surface) or None
    except Exception:
        return None


def is_loopback_approval_url(url: str) -> bool:
    try:
        parsed = urlparse(url)
    except ValueError:
        return False
    host = (parsed.hostname or "").lower()
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    return parsed.scheme in {"http", "https"} and host in _LOOPBACK_HOSTS
