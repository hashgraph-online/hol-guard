"""Installed Cursor hook copy that always includes the local approval URL."""

from __future__ import annotations

HOOK_SCRIPT_TEMPLATE_REASON = """
def _cursor_review_url(guard_payload: dict[str, object]) -> str | None:
    for key in ("primary_approval_url", "approval_url", "guardApprovalUrl"):
        value = guard_payload.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    queued = guard_payload.get("approval_requests")
    if isinstance(queued, list):
        for item in queued:
            value = item.get("approval_url") if isinstance(item, Mapping) else None
            if isinstance(value, str) and value.strip():
                return value.strip()
    return None


def _cursor_reason(guard_payload: dict[str, object]) -> str:
    review_url = _cursor_review_url(guard_payload)
    candidates: list[object] = [
        guard_payload.get(key)
        for key in (
            "reason",
            "stopReason",
            "systemMessage",
            "review_hint",
            "risk_summary",
            "why_now",
            "risk_headline",
        )
    ]
    hook_output = guard_payload.get("hookSpecificOutput")
    if isinstance(hook_output, Mapping):
        candidates.append(hook_output.get("permissionDecisionReason"))
    decision = guard_payload.get("decision_v2_json")
    if isinstance(decision, Mapping):
        candidates.extend(
            decision.get(key)
            for key in ("harness_message", "retry_instruction", "user_body", "user_title")
        )
    reason = next(
        (value.strip() for value in candidates if isinstance(value, str) and value.strip()),
        None,
    )
    suffix = ""
    if review_url is not None:
        suffix = "Open HOL Guard to approve or keep this blocked: " + review_url + "."
    if reason is None:
        if suffix:
            return "HOL Guard needs approval for this Cursor action. " + suffix
        return "HOL Guard blocked this Cursor action."
    if not suffix or review_url in reason:
        return reason
    return f"{reason} {suffix}"

"""
