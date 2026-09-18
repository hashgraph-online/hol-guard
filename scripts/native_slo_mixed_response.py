"""Frozen delivered-response proof for the mixed Codex/Claude HTTP routes."""

from __future__ import annotations

from collections.abc import Mapping


def delivered_decision(event: str, response: Mapping[str, object]) -> str | None:
    """A missing/contradictory permission field is never a proven denial."""
    specific = response.get("hookSpecificOutput")
    if not isinstance(specific, Mapping) or specific.get("hookEventName") != event:
        return None
    action = response.get("policy_action")
    if event == "PreToolUse":
        permission = specific.get("permissionDecision")
        if (
            permission == "allow"
            and action in ("allow", "warn")
            and response.get("continue") is True
            and response.get("decision") in (None, "allow")
            and response.get("model_output_action") in (None, "not_applicable")
        ):
            return "allow"
        if permission == "deny" and action == "block" and response.get("decision") in (None, "deny", "block"):
            return "deny"
    if event == "PostToolUse":
        if (
            action in ("allow", "warn")
            and response.get("decision") is None
            and response.get("model_output_action") is None
            and (response.get("continue") is None or response.get("continue") is True)
        ):
            return "allow"
        if action == "block" and response.get("decision") == "block" and response.get("model_output_action") == "block":
            return "deny"
    return None
