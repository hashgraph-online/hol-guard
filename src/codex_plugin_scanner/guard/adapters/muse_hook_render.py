"""Carry the resident's Muse hook document to Muse's stdout.

The document and its exit status come from the native runtime
(``hook_responses::muse``); nothing here reads a verdict. A resident that
cannot answer leaves the call blocked.

Muse hooks speak the Claude-Code-shaped JSON contract, verified
against Muse 1.4.14 with ``muse plugins hook test`` and a live
``muse exec`` run:

- An allow is empty stdout with exit 0. An explicit
  ``permissionDecision: "allow"`` without ``updatedInput`` is rejected by
  Muse, so Guard never emits a bare allow.
- A ``PreToolUse`` block is ``hookSpecificOutput.permissionDecision:
  "deny"`` with a reason, or exit 2 with the reason on stderr. Guard uses
  the JSON form on exit 0 so the reason reaches the model.
- A ``UserPromptSubmit`` block is ``{"decision": "block", "reason": ...}``.
- ``PostToolUse`` and ``SessionStart`` cannot undo or block; Guard adds
  ``additionalContext`` and otherwise stays silent.
- ``PermissionRequest`` defers to Muse's own prompt (no decision)
  unless Guard's final answer is a block.

Approval resume: when the daemon queues a ``review`` for a ``PreToolUse``
call, the bounded bridge waits for the approval inside the hook (the
Oh My Pi model: the user approves once and the work continues without a
manual retry). An approval rewrites the answer to an allow for the
identical call; a denial keeps it blocked. The one-time approval binding
still rejects any call whose arguments changed while waiting.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import TYPE_CHECKING

from ..native_hook_render import native_muse_bridge

if TYPE_CHECKING:
    from ..store import GuardStore

_MUSE_WAITABLE_ACTIONS = frozenset({"review", "require-reapproval"})
_UNAVAILABLE_REASON = "HOL Guard blocked this action."


def _compact(event_name: str) -> str:
    return event_name.replace("_", "").replace("-", "").lower()


def muse_bridge_response(
    daemon_response: Mapping[str, object],
    *,
    event_name: str,
    guard_home: Path | None = None,
    deadline: float | None = None,
) -> tuple[str, str, int]:
    """Print the resident's Muse document for this daemon answer.

    Reading an answer is a verdict about a verdict, so the resident does it
    and this returns what it rendered. A resident that cannot answer leaves
    the call blocked: Muse reads exit 2 with a reason on stderr as a refusal
    on every deciding event.
    """

    rendered = native_muse_bridge(daemon_response, event_name=event_name, guard_home=guard_home, deadline=deadline)
    if rendered is None:
        return "", _UNAVAILABLE_REASON, 2
    document, exit_code = rendered
    if document is None:
        return "", "", exit_code
    return json.dumps(document, ensure_ascii=True, separators=(",", ":")), "", exit_code


def approval_request_ids(response: Mapping[str, object]) -> list[str]:
    """Approval request ids named by a daemon review answer."""

    ids: list[str] = []
    for key in ("primary_approval_request_id", "approval_request_id", "guardApprovalRequestId"):
        value = response.get(key)
        if isinstance(value, str) and value.strip() and value.strip() not in ids:
            ids.append(value.strip())
    requests = response.get("approval_requests")
    if isinstance(requests, list):
        for item in requests:
            value = item.get("request_id") or item.get("id") if isinstance(item, Mapping) else item
            if isinstance(value, str) and value.strip() and value.strip() not in ids:
                ids.append(value.strip())
    return ids


def apply_muse_pretool_approval_wait(
    response: dict[str, object],
    *,
    event_name: str,
    store: GuardStore,
    timeout_seconds: int,
) -> dict[str, object]:
    """Wait for a queued Muse approval and rewrite the answer in place.

    Mirrors ``apply_grok_pretool_approval_wait``: an approval lets the
    original ``PreToolUse`` call proceed unchanged (approval resume); a
    denial keeps it blocked; a still-pending approval returns the review
    unchanged so Muse shows the block and the saved approval answers the
    retry.
    """

    if _compact(event_name) != "pretooluse":
        return response
    if str(response.get("policy_action") or "") not in _MUSE_WAITABLE_ACTIONS:
        return response
    request_ids = approval_request_ids(response)
    if not request_ids or timeout_seconds <= 0:
        return response
    from ..approvals import wait_for_approval_requests

    wait_result = wait_for_approval_requests(
        store=store,
        request_ids=request_ids,
        timeout_seconds=timeout_seconds,
    )
    response["approval_wait"] = wait_result
    if not bool(wait_result.get("resolved")):
        response["review_hint"] = (
            "Approval is still pending in HOL Guard. Approve it, and Muse will resume this exact tool call."
        )
        return response
    items = wait_result.get("items")
    resolved = [item for item in (items if isinstance(items, list) else []) if isinstance(item, dict)]
    if not resolved or any(str(item.get("resolution_action")) != "allow" for item in resolved):
        blocked = dict(response)
        blocked["decision"] = "deny"
        blocked["policy_action"] = "block"
        blocked["review_hint"] = "HOL Guard kept this Muse action blocked."
        hook_specific = blocked.get("hookSpecificOutput")
        if isinstance(hook_specific, Mapping):
            rewritten = dict(hook_specific)
            rewritten["permissionDecision"] = "deny"
            blocked["hookSpecificOutput"] = rewritten
        return blocked
    allowed = dict(response)
    allowed["decision"] = "allow"
    allowed["policy_action"] = "allow"
    allowed.pop("reason", None)
    allowed["browser_resolution_request_id"] = request_ids[0]
    allowed["review_hint"] = "Approval received in HOL Guard. Muse is resuming this action."
    hook_specific = allowed.get("hookSpecificOutput")
    if isinstance(hook_specific, Mapping):
        rewritten = dict(hook_specific)
        rewritten.pop("permissionDecision", None)
        rewritten.pop("permissionDecisionReason", None)
        allowed["hookSpecificOutput"] = rewritten
    return allowed


__all__ = [
    "apply_muse_pretool_approval_wait",
    "approval_request_ids",
    "muse_bridge_response",
]
