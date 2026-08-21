"""Hold a Codex PreToolUse hook until HOL Guard records the browser decision.

The daemon hook worker must return in a tight budget, so Codex previously
denied the tool and then failed to continue the same CLI turn. This module
lets the longer-lived hook bridge poll the local daemon, matching Oh My Pi's
approve-then-continue flow without starting a second Codex run.
"""

from __future__ import annotations

import sys
import time
from collections.abc import Mapping
from pathlib import Path
from urllib.parse import quote

from ..browser_opener import open_browser_url
from .codex_daemon_hook_transport import _daemon_json_get

GUARD_APPROVAL_REQUEST_ID_KEY = "guardApprovalRequestId"
GUARD_APPROVAL_URL_KEY = "guardApprovalUrl"
_POLL_INTERVAL_SECONDS = 0.2
_GET_TIMEOUT_CAP_SECONDS = 1.5


def apply_browser_approval_wait(
    response: dict[str, object],
    *,
    event_name: str,
    state_path: str | Path,
    deadline: float,
) -> dict[str, object]:
    """Replace a pending PreToolUse deny with allow once the browser approves."""

    pending = pending_pretool_approval(response, event_name=event_name)
    if pending is None:
        return response
    request_id, approval_url = pending
    _open_pending_approval(approval_url, state_path=state_path)
    action = _poll_resolution(
        request_id=request_id,
        state_path=state_path,
        deadline=deadline,
    )
    if action == "allow":
        return allow_pretool_response()
    return response


def pending_pretool_approval(
    response: Mapping[str, object],
    *,
    event_name: str,
) -> tuple[str, str | None] | None:
    if event_name != "PreToolUse":
        return None
    hook_output = response.get("hookSpecificOutput")
    if not isinstance(hook_output, Mapping):
        return None
    if hook_output.get("permissionDecision") != "deny":
        return None
    request_id = _optional_safe_request_id(response.get(GUARD_APPROVAL_REQUEST_ID_KEY))
    if request_id is None:
        return None
    approval_url = _optional_http_url(response.get(GUARD_APPROVAL_URL_KEY))
    return request_id, approval_url


def allow_pretool_response() -> dict[str, object]:
    return {"hookSpecificOutput": {"hookEventName": "PreToolUse"}}


def _poll_resolution(
    *,
    request_id: str,
    state_path: str | Path,
    deadline: float,
) -> str | None:
    path = f"/v1/requests/{quote(request_id, safe='')}"
    while True:
        remaining = deadline - time.monotonic()
        if remaining < _POLL_INTERVAL_SECONDS:
            return None
        try:
            payload = _daemon_json_get(
                state_path=state_path,
                path=path,
                timeout_seconds=min(remaining, _GET_TIMEOUT_CAP_SECONDS),
            )
        except (OSError, TimeoutError, ValueError):
            payload = None
        action = _resolution_action(payload)
        if action in {"allow", "block"}:
            return action
        time.sleep(min(_POLL_INTERVAL_SECONDS, max(0.0, deadline - time.monotonic())))


def _open_pending_approval(approval_url: str | None, *, state_path: str | Path) -> None:
    if approval_url is None:
        return
    print(f"HOL Guard is waiting for approval in your browser: {approval_url}", file=sys.stderr, flush=True)
    browser_url = approval_url
    try:
        from ..approvals import build_approval_browser_url
        from ..daemon.manager import load_guard_daemon_auth_token

        browser_url = (
            build_approval_browser_url(
                approval_url,
                auth_token=load_guard_daemon_auth_token(Path(state_path).parent),
            )
            or approval_url
        )
    except Exception:
        browser_url = approval_url
    try:
        open_browser_url(browser_url)
    except Exception:
        return


def _resolution_action(payload: Mapping[str, object] | None) -> str | None:
    if not isinstance(payload, Mapping) or payload.get("status") != "resolved":
        return None
    action = payload.get("resolution_action")
    if action == "allow":
        return "allow"
    if action in {"block", "deny", "denied", "blocked"}:
        return "block"
    return None


def _optional_safe_request_id(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    request_id = value.strip()
    if not (8 <= len(request_id) <= 128):
        return None
    if any(not (char.isalnum() or char in "-_") for char in request_id):
        return None
    return request_id


def _optional_http_url(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    url = value.strip()
    if not url.startswith("http://") and not url.startswith("https://"):
        return None
    if any(char.isspace() for char in url):
        return None
    return url


__all__ = [
    "GUARD_APPROVAL_REQUEST_ID_KEY",
    "GUARD_APPROVAL_URL_KEY",
    "allow_pretool_response",
    "apply_browser_approval_wait",
    "pending_pretool_approval",
]
