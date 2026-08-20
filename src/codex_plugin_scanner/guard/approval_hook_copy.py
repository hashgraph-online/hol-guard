"""User-facing approval links for live harness hook output."""

from __future__ import annotations

from pathlib import Path
from urllib.parse import urlparse

from .approvals import build_approval_browser_url
from .daemon.manager import load_guard_daemon_auth_token

_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1", "localhost"})
_OPEN_GUARD_MARKER = "open hol guard to approve"
_DEFAULT_HOOK_REASON = "HOL Guard flagged this tool call for review."


def is_loopback_approval_url(url: str) -> bool:
    try:
        parsed = urlparse(url)
    except ValueError:
        return False
    host = (parsed.hostname or "").lower()
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    return parsed.scheme in {"http", "https"} and host in _LOOPBACK_HOSTS


def join_native_hook_reason(*values: object | None) -> str:
    """Join hook reason parts, keeping the tokenized Open-HOL-Guard copy when both exist."""

    messages: list[str] = []
    for value in values:
        if isinstance(value, str) and value.strip():
            candidate = value.strip()
            if candidate not in messages:
                messages.append(candidate)
    has_tokenized = any(
        "guard-token=" in message.lower() and _OPEN_GUARD_MARKER in message.lower() for message in messages
    )
    if has_tokenized:
        messages = [
            message
            for message in messages
            if _OPEN_GUARD_MARKER not in message.lower() or "guard-token=" in message.lower()
        ]
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
    token = load_guard_daemon_auth_token(guard_home)
    if message is None or not token:
        return message
    from .cli.commands_support_interaction import _preferred_approval_review_url

    approval_center_url = response_payload.get("approval_center_url")
    if not isinstance(approval_center_url, str) or not approval_center_url.strip():
        return message
    review_url = _preferred_approval_review_url(response_payload, harness=harness) or approval_center_url.strip()
    if not is_loopback_approval_url(review_url):
        return message
    tokenized = build_approval_browser_url(review_url, auth_token=token)
    if not tokenized or tokenized == review_url:
        return message
    return message.replace(review_url, tokenized, 1)
