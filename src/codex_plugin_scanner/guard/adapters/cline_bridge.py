"""Shared Cline hook/plugin bridge behavior."""

from __future__ import annotations

import json
from collections.abc import Mapping

_BLOCK_DECISIONS = frozenset({"deny", "block", "ask"})
_REVIEW_ACTIONS = frozenset({"review", "require-reapproval", "sandbox-required", "block"})


def _json_object_from_output(stdout: str) -> dict[str, object] | None:
    stripped = stdout.strip()
    if not stripped:
        return None
    candidates = [stripped, *reversed([line.strip() for line in stripped.splitlines() if line.strip()])]
    for candidate in candidates:
        if not candidate.startswith("{"):
            continue
        try:
            parsed = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict):
            return {str(key): value for key, value in parsed.items() if isinstance(key, str)}
    return None


def cline_control_from_guard_output(
    stdout: str,
    *,
    event_name: str,
    default_error: str = "HOL Guard could not verify this action safely.",
) -> dict[str, object]:
    """Translate Guard's native hook response into Cline's cancel contract."""

    payload = _json_object_from_output(stdout)
    if payload is None:
        if event_name == "PreToolUse":
            return {"cancel": True, "errorMessage": default_error, "contextModification": default_error}
        return {"cancel": False}

    reason = _reason(payload) or default_error
    blocked = _payload_blocks(payload)
    if event_name == "PreToolUse":
        return {
            "cancel": blocked,
            "errorMessage": reason if blocked else "",
            "contextModification": reason if blocked else "",
        }
    return {"cancel": False, "contextModification": reason if blocked else ""}


def plugin_before_tool_control(stdout: str) -> dict[str, object] | None:
    """Return a typed Cline plugin beforeTool result, failing closed on ambiguity."""

    payload = _json_object_from_output(stdout)
    if payload is None:
        return {"skip": True, "reason": "HOL Guard could not verify this action safely."}
    if _payload_blocks(payload):
        return {"skip": True, "reason": _reason(payload) or "HOL Guard blocked this action."}
    return None


def plugin_after_tool_replacement(stdout: str) -> dict[str, object] | None:
    """Return a safe replacement result when Guard blocks/reviews tool output."""

    payload = _json_object_from_output(stdout)
    if payload is None:
        return {
            "result": {
                "output": "HOL Guard withheld this tool result because output review did not complete safely.",
                "isError": True,
            }
        }
    if not _payload_blocks(payload):
        replacement = _replacement_text(payload)
        if replacement is None:
            return None
        return {"result": {"output": replacement, "isError": False}}
    return {
        "result": {
            "output": _reason(payload) or "HOL Guard withheld this tool result.",
            "isError": True,
        }
    }


def _payload_blocks(payload: Mapping[str, object]) -> bool:
    if payload.get("blocked") is True or payload.get("continue") is False:
        return True
    decision = payload.get("decision")
    if isinstance(decision, str) and decision.lower() in _BLOCK_DECISIONS:
        return True
    policy_action = payload.get("policy_action") or payload.get("policyAction")
    if isinstance(policy_action, str) and policy_action.lower() in _REVIEW_ACTIONS:
        return True
    hook_specific = payload.get("hookSpecificOutput")
    if isinstance(hook_specific, Mapping):
        permission = hook_specific.get("permissionDecision")
        if isinstance(permission, str) and permission.lower() in _BLOCK_DECISIONS:
            return True
        nested_decision = hook_specific.get("decision")
        if isinstance(nested_decision, Mapping):
            behavior = nested_decision.get("behavior")
            if isinstance(behavior, str) and behavior.lower() in _BLOCK_DECISIONS:
                return True
    return False


def _reason(payload: Mapping[str, object]) -> str | None:
    for key in ("reason", "stopReason", "review_hint", "systemMessage", "message", "error"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    hook_specific = payload.get("hookSpecificOutput")
    if isinstance(hook_specific, Mapping):
        for key in ("permissionDecisionReason", "additionalContext"):
            value = hook_specific.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
        decision = hook_specific.get("decision")
        if isinstance(decision, Mapping):
            value = decision.get("message")
            if isinstance(value, str) and value.strip():
                return value.strip()
    return None


def _replacement_text(payload: Mapping[str, object]) -> str | None:
    for key in ("reviewed_output", "reviewedOutput", "safe_output", "safeOutput", "replacement", "excerpt"):
        value = payload.get(key)
        if isinstance(value, str) and value:
            return value
    return None


__all__ = [
    "cline_control_from_guard_output",
    "plugin_after_tool_replacement",
    "plugin_before_tool_control",
]
