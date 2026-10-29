"""Render Guard daemon answers in Muse's hook wire format.

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

from ..action_lattice import normalize_guard_action

if TYPE_CHECKING:
    from ..store import GuardStore

_MUSE_WAITABLE_ACTIONS = frozenset({"review", "require-reapproval"})
_RESTRICTIVE_ACTIONS = frozenset({"review", "require-reapproval", "sandbox-required", "block"})
# Events where Guard's answer decides whether the work happens. An answer that
# names no verdict is treated as restrictive on these and as silence elsewhere.
_DECIDING_EVENTS = frozenset({"pretooluse", "permissionrequest", "userpromptsubmit"})
_SESSION_CONTEXT = "HOL Guard protection is active for this workspace."
_UNREADABLE_VERDICT = "HOL Guard could not read a verdict for this action."


def _compact(event_name: str) -> str:
    return event_name.replace("_", "").replace("-", "").lower()


def _behavior(word: str) -> str | None:
    word = word.strip().lower()
    if word == "allow":
        return "allow"
    if word in {"deny", "block"}:
        return "block"
    if word == "ask":
        return "review"
    return None


def _action(response: Mapping[str, object]) -> str | None:
    """Guard's action for this answer, or ``None`` when it names no verdict.

    An unknown ``policy_action`` normalizes to ``review`` rather than passing
    through, and an answer that carries no verdict at all stays ``None`` so the
    caller can fail closed on the events that enforce one.
    """

    policy_action = response.get("policy_action")
    if isinstance(policy_action, str) and policy_action.strip():
        return normalize_guard_action(policy_action.strip())
    decision = response.get("decision")
    if isinstance(decision, str):
        word = _behavior(decision)
        if word is not None:
            return word
    hook_specific = response.get("hookSpecificOutput")
    if isinstance(hook_specific, Mapping):
        nested = hook_specific.get("permissionDecision")
        if isinstance(nested, str):
            word = _behavior(nested)
            if word is not None:
                return word
        # The PermissionRequest envelope carries its verdict one level deeper.
        nested_decision = hook_specific.get("decision")
        if isinstance(nested_decision, Mapping):
            behavior = nested_decision.get("behavior")
            if isinstance(behavior, str):
                word = _behavior(behavior)
                if word is not None:
                    return word
    # An answer that carries no verdict but tells Muse to continue is the
    # unmanaged passthrough: Guard has nothing to say about this harness.
    proceed = response.get("continue")
    if proceed is True:
        return "allow"
    if proceed is False:
        return "block"
    return None


def _reason(response: Mapping[str, object], action: str | None) -> str:
    for key in ("reason", "permission_decision_reason"):
        value = response.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    hook_specific = response.get("hookSpecificOutput")
    if isinstance(hook_specific, Mapping):
        value = hook_specific.get("permissionDecisionReason")
        if isinstance(value, str) and value.strip():
            return value.strip()
    if action is None:
        return _UNREADABLE_VERDICT
    return f"HOL Guard blocked this action ({action})"


def _additional_context(response: Mapping[str, object]) -> str | None:
    hook_specific = response.get("hookSpecificOutput")
    if isinstance(hook_specific, Mapping):
        value = hook_specific.get("additionalContext")
        if isinstance(value, str) and value.strip():
            return value.strip()
    value = response.get("additional_context")
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def muse_bridge_response(
    daemon_response: Mapping[str, object],
    *,
    event_name: str,
    guard_home: Path | None = None,
    deadline: float | None = None,
) -> tuple[str, str, int]:
    """Turn a daemon answer into Muse stdout, stderr, and exit code."""

    del guard_home, deadline
    action = _action(daemon_response)
    event = _compact(event_name)
    restrictive = event in _DECIDING_EVENTS if action is None else action in _RESTRICTIVE_ACTIONS

    if event == "userpromptsubmit":
        if restrictive:
            payload = {"decision": "block", "reason": _reason(daemon_response, action)}
            return json.dumps(payload, ensure_ascii=True, separators=(",", ":")), "", 0
        context = _additional_context(daemon_response)
        if context is not None:
            payload = {"hookSpecificOutput": {"hookEventName": "UserPromptSubmit", "additionalContext": context}}
            return json.dumps(payload, ensure_ascii=True, separators=(",", ":")), "", 0
        return "", "", 0

    if event in {"pretooluse", "permissionrequest"}:
        if not restrictive:
            return "", "", 0
        if event == "permissionrequest" and action in _MUSE_WAITABLE_ACTIONS:
            # Defer to Muse's own approval prompt; the PreToolUse verdict
            # for the same call remains the decision boundary.
            return "", "", 0
        payload = {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse" if event == "pretooluse" else "PermissionRequest",
                "permissionDecision": "deny",
                "permissionDecisionReason": _reason(daemon_response, action),
            }
        }
        return json.dumps(payload, ensure_ascii=True, separators=(",", ":")), "", 0

    # Observation events (PostToolUse, SessionStart, lifecycle): never a
    # decision; add review context when Guard has something to say.
    context = _additional_context(daemon_response)
    if context is None and restrictive:
        context = _reason(daemon_response, action)
    if context is None and event == "sessionstart":
        context = _SESSION_CONTEXT
    if context is None:
        return "", "", 0
    canonical = {"sessionstart": "SessionStart", "stop": "Stop"}.get(event, "PostToolUse")
    payload = {"hookSpecificOutput": {"hookEventName": canonical, "additionalContext": context}}
    return json.dumps(payload, ensure_ascii=True, separators=(",", ":")), "", 0


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
