"""User-facing approval links for live harness hook output."""

from __future__ import annotations

import re
import shlex
from collections.abc import Mapping
from pathlib import Path
from urllib.parse import urlparse

from .approvals import build_approval_browser_url
from .daemon.manager import load_guard_daemon_auth_token

_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1", "localhost"})
_OPEN_GUARD_MARKER = "open hol guard to approve"
_DEFAULT_HOOK_REASON = "HOL Guard flagged this tool call for review."
_GUARD_TOKEN_FRAGMENT = re.compile(
    r"#guard-token=(?:[A-Za-z0-9_~%+-]+\.)*[A-Za-z0-9_~%+-]+",
    re.IGNORECASE,
)


def _without_guard_token_fragment(text: str) -> str:
    return _GUARD_TOKEN_FRAGMENT.sub("", text)


def is_loopback_approval_url(url: str) -> bool:
    try:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        port = parsed.port
    except ValueError:
        return False
    if port is not None and not 0 <= port <= 65535:
        return False
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    return (
        parsed.scheme in {"http", "https"}
        and host in _LOOPBACK_HOSTS
        and parsed.username is None
        and parsed.password is None
    )


def _safe_approval_request_id(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    request_id = value.strip()
    if not request_id or len(request_id) > 256 or not request_id.isprintable():
        return None
    return request_id


def _approval_recovery_command(response_payload: Mapping[str, object], *, review_url: str | None = None) -> str | None:
    """Return a shell-safe local command for recovering a pending approval."""

    queued = response_payload.get("approval_requests")
    if isinstance(queued, list):
        queued_ids: list[str] = []
        for item in queued:
            if not isinstance(item, Mapping):
                continue
            request_id = _safe_approval_request_id(item.get("request_id"))
            if request_id is None:
                continue
            item_url = item.get("approval_url")
            if review_url is not None and isinstance(item_url, str) and item_url.strip() == review_url:
                return shlex.join(["hol-guard", "approvals", "open", request_id])
            queued_ids.append(request_id)
        if len(queued_ids) == 1:
            return shlex.join(["hol-guard", "approvals", "open", queued_ids[0]])

    request_id = _safe_approval_request_id(response_payload.get("primary_approval_request_id"))
    if request_id is None:
        request_id = _safe_approval_request_id(response_payload.get("request_id"))
    if request_id is None:
        return None
    return shlex.join(["hol-guard", "approvals", "open", request_id])


def join_native_hook_reason(*values: object | None) -> str:
    """Join hook reason parts, keeping the tokenized Open-HOL-Guard copy when both exist."""

    messages: list[str] = []
    for value in values:
        if isinstance(value, str) and value.strip():
            candidate = value.strip()
            if candidate not in messages:
                messages.append(candidate)
    tokenized = [
        message for message in messages if "guard-token=" in message.lower() and _OPEN_GUARD_MARKER in message.lower()
    ]
    if tokenized:
        replacement = tokenized[0]
        untokenized = _without_guard_token_fragment(replacement)
        merged: list[str] = []
        used_replacement = False
        for message in messages:
            if message == replacement:
                if not used_replacement:
                    merged.append(message)
                    used_replacement = True
                continue
            if untokenized and untokenized in message:
                merged.append(message.replace(untokenized, replacement, 1))
                used_replacement = True
                continue
            merged.append(message)
        messages = []
        for candidate in merged:
            if candidate not in messages:
                messages.append(candidate)
    if messages:
        return " ".join(messages)
    return _DEFAULT_HOOK_REASON


def live_hook_approval_context(
    response_payload: dict[str, object],
    *,
    harness: str,
    guard_home: Path,
) -> str | None:
    """Build ephemeral hook copy with a loopback-only scoped dashboard token."""

    from .cli.commands_support_runtime_policy import _native_approval_center_context

    message = _native_approval_center_context(response_payload, harness=harness)
    if message is None:
        return message
    from .cli.commands_support_interaction import _preferred_approval_review_url

    approval_center_url = response_payload.get("approval_center_url")
    if not isinstance(approval_center_url, str) or not approval_center_url.strip():
        return message
    review_url = _preferred_approval_review_url(response_payload, harness=harness) or approval_center_url.strip()
    if not is_loopback_approval_url(review_url):
        return message
    tokenized = live_approval_browser_url(review_url, guard_home=guard_home)
    if tokenized is None or tokenized == review_url:
        return message.replace(review_url, "the local Guard app", 1)
    return message.replace(review_url, tokenized, 1)


def live_approval_browser_url(url: str, *, guard_home: Path) -> str | None:
    """Return a signed loopback link for live presentation, never persisted output."""
    if not is_loopback_approval_url(url):
        return None
    token = load_guard_daemon_auth_token(guard_home)
    if not token:
        return None
    try:
        return build_approval_browser_url(url, auth_token=token)
    except (TypeError, ValueError):
        return None
