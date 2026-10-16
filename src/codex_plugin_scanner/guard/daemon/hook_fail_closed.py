"""Hook responses the daemon renders itself.

Rust renders every real hook response. This module keeps only the fixed,
deny-only payloads used when the resident cannot render one. It never computes
an allow and never mirrors Rust decision logic: it picks the envelope the
harness can parse and fills in a fixed deny.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path

from ..approval_link_output import native_review_reason
from ..native_hook_render import (
    native_render_pre_tool,
    native_render_pre_tool_review,
    native_render_recording_only_pre_tool,
)

RENDER_UNAVAILABLE_REASON_CODE = "native_hook_render_unavailable"
RENDER_UNAVAILABLE_REASON = "HOL Guard could not complete native review safely."
_REVIEW_DEFAULT_REASON = "HOL Guard requires review before this action can execute."
PROMPT_UNAVAILABLE_REASON_CODE = "native_prompt_unavailable"
PROMPT_UNAVAILABLE_REASON = "HOL Guard could not complete native prompt review safely."
_FLAT_DENY_HARNESSES = frozenset({"pi", "omp", "grok", "hermes", "openclaw"})
_DECISION_HARNESSES = frozenset({"pi", "omp", "hermes", "openclaw"})
_PROMPT_EVENTS = frozenset({"userpromptsubmit", "userpromptsubmitted"})
_PRE_TOOL_EVENTS = frozenset({"pretooluse", "pretool", "pretoolcall"})
_PERMISSION_EVENTS = frozenset({"permissionrequest", "permissionrequestv2", "copilotpermissionrequest"})


def canonical_harness(harness: str) -> str:
    return harness.strip().lower().replace("_", "-")


def fail_closed_pre_tool(
    harness: str,
    *,
    reason: str = RENDER_UNAVAILABLE_REASON,
    reason_code: str = RENDER_UNAVAILABLE_REASON_CODE,
) -> dict[str, object]:
    """A fixed PreToolUse deny in the harness envelope."""

    canonical = canonical_harness(harness)
    if canonical in _FLAT_DENY_HARNESSES:
        return {
            "decision": "block" if canonical == "hermes" else "deny",
            "reason": reason,
            "policy_action": "block",
            "reason_code": reason_code,
        }
    return {
        "policy_action": "block",
        "reason_code": reason_code,
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        },
    }


def _deadline_kwargs(deadline: float | None) -> dict[str, float]:
    return {} if deadline is None else {"deadline": deadline}


def render_pre_tool(
    harness: str, verdict: Mapping[str, object], *, guard_home: Path | None = None, deadline: float | None = None
) -> dict[str, object]:
    """Resident-rendered PreToolUse response, or a fixed deny when it cannot render."""

    rendered = native_render_pre_tool(harness, verdict, guard_home=guard_home, **_deadline_kwargs(deadline))
    return rendered or fail_closed_pre_tool(harness)


def render_accepted_allow(
    harness: str, allowed: Mapping[str, object], *, guard_home: Path | None = None, deadline: float | None = None
) -> dict[str, object]:
    """Render an allow that rests on a saved or local approval.

    Only a reply the resident actually rendered is marked as an accepted reuse.
    When the resident cannot render, the fixed deny carries no reuse status, so
    the activity record never says an approval was accepted for a blocked action.
    """

    rendered = native_render_pre_tool(harness, allowed, guard_home=guard_home, **_deadline_kwargs(deadline))
    if rendered is None:
        return fail_closed_pre_tool(harness)
    rendered["approval_reuse_status"] = "accepted"
    return rendered


def render_pre_tool_review(
    harness: str,
    verdict: Mapping[str, object],
    *,
    approval: Mapping[str, object] | None,
    guard_home: Path | None = None,
    deadline: float | None = None,
) -> dict[str, object]:
    """Resident-rendered paused review, or a fixed deny when it cannot render.

    The fixed deny keeps the signed approval link in its reason, so a review that
    is already queued still tells the user where to approve it.
    """

    linked_reason = None
    raw_url = approval.get("approval_url") if approval is not None else None
    if isinstance(raw_url, str) and raw_url.strip():
        linked_reason = native_review_reason(
            canonical_harness(harness),
            str(verdict.get("reason") or _REVIEW_DEFAULT_REASON),
            raw_url.strip(),
            guard_home=guard_home,
        )
    rendered = native_render_pre_tool_review(
        harness,
        verdict,
        approval=approval,
        linked_reason=linked_reason,
        guard_home=guard_home,
        **_deadline_kwargs(deadline),
    )
    return rendered or fail_closed_pre_tool(harness, reason=linked_reason or RENDER_UNAVAILABLE_REASON)


def render_recording_only_pre_tool(
    harness: str,
    *,
    reason_code: str,
    reason: str,
    guard_home: Path | None = None,
    deadline: float | None = None,
    fallback: dict[str, object] | None = None,
) -> dict[str, object]:
    """Resident-rendered Watch continue, or a fixed deny when it cannot render."""

    rendered = native_render_recording_only_pre_tool(
        harness,
        reason_code=reason_code,
        reason=reason,
        guard_home=guard_home,
        **_deadline_kwargs(deadline),
    )
    return rendered or fallback or fail_closed_pre_tool(harness)


def _compact(event_name: str) -> str:
    return event_name.strip().lower().replace("_", "").replace("-", "")


def fail_closed_response(
    harness: str,
    event_name: str,
    *,
    reason: str = RENDER_UNAVAILABLE_REASON,
    reason_code: str = RENDER_UNAVAILABLE_REASON_CODE,
    prompt_reason: str | None = None,
) -> dict[str, object]:
    """Fixed response when the resident cannot answer a hook.

    Prompt, permission and tool events get a constant deny in the harness
    envelope. Other events observe activity that already happened, so they get
    a constant payload that carries no verdict. Nothing here reads the payload
    or the posture, and nothing here ever authorizes an action.
    """

    canonical = canonical_harness(harness)
    compact = _compact(event_name)
    if compact in _PROMPT_EVENTS:
        prompt_text = prompt_reason or PROMPT_UNAVAILABLE_REASON
        if canonical == "copilot":
            return {
                "behavior": "deny",
                "message": prompt_text,
                "interrupt": False,
                "policy_action": "block",
                "reason_code": PROMPT_UNAVAILABLE_REASON_CODE,
            }
        return {
            "decision": "block",
            "reason": prompt_text,
            "systemMessage": prompt_text,
            "policy_action": "block",
            "reason_code": PROMPT_UNAVAILABLE_REASON_CODE,
            "hookSpecificOutput": {"hookEventName": "UserPromptSubmit"},
        }
    if compact in _PERMISSION_EVENTS:
        if canonical == "copilot":
            return {"behavior": "deny", "message": reason, "interrupt": False, "reason_code": reason_code}
        if canonical in _FLAT_DENY_HARNESSES:
            return fail_closed_pre_tool(harness, reason=reason, reason_code=reason_code)
        return {
            "reason_code": reason_code,
            "hookSpecificOutput": {
                "hookEventName": "PermissionRequest",
                "decision": {"behavior": "deny", "message": reason},
            },
        }
    if compact in _PRE_TOOL_EVENTS or compact.startswith("before"):
        return fail_closed_pre_tool(harness, reason=reason, reason_code=reason_code)
    if canonical == "grok":
        return {}
    if canonical in _DECISION_HARNESSES:
        return {"decision": "allow", "policy_action": "allow", "reason_code": reason_code}
    return {
        "continue": True,
        "policy_action": "allow",
        "reason_code": reason_code,
        "hookSpecificOutput": {"hookEventName": event_name},
    }


def unmanaged_passthrough(harness: str) -> dict[str, object]:
    """Constant reply for a hook that belongs to an app Guard does not manage."""

    canonical = canonical_harness(harness)
    if canonical == "grok":
        return {}
    if canonical in _DECISION_HARNESSES:
        return {"decision": "allow", "reason_code": "harness_not_managed"}
    return {"continue": True, "reason_code": "harness_not_managed"}
