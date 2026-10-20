"""Shape daemon responses into Codex's strict hook output schemas."""

from __future__ import annotations

from collections.abc import Mapping


def codex_hook_response(response: Mapping[str, object], *, event_name: str) -> dict[str, object]:
    """Keep daemon metadata out of Codex's strict hook response schemas."""

    universal_keys = {"continue", "stopReason", "suppressOutput", "systemMessage"}
    event_keys = {
        "PostToolUse": {"decision", "reason"},
    }.get(event_name, set())
    allowed_keys = universal_keys | event_keys | {"hookSpecificOutput"}
    filtered = {key: value for key, value in response.items() if key in allowed_keys}
    hook_output = filtered.get("hookSpecificOutput")
    if event_name == "PostToolUse":
        if not isinstance(hook_output, Mapping):
            filtered.pop("hookSpecificOutput", None)
        else:
            post_tool_keys = {"hookEventName", "additionalContext", "updatedMCPToolOutput"}
            filtered["hookSpecificOutput"] = {key: value for key, value in hook_output.items() if key in post_tool_keys}
        return filtered
    if event_name == "PreToolUse" and "hookSpecificOutput" in filtered:
        cleaned: dict[str, object] = {"hookEventName": event_name}
        if isinstance(hook_output, Mapping):
            decision = hook_output.get("permissionDecision")
            normalized = decision.strip().lower() if isinstance(decision, str) else ""
            if response.get("policy_action") == "deny":
                normalized = "deny"
            reason = hook_output.get("permissionDecisionReason")
            updated_input = hook_output.get("updatedInput")
            if normalized in {"deny", "ask"}:
                cleaned["permissionDecision"] = normalized
                if isinstance(reason, str) and reason:
                    cleaned["permissionDecisionReason"] = reason
            elif normalized == "allow" and isinstance(updated_input, Mapping):
                # Only the contained-test route rewrites input: the sink rechecks native authority.
                cleaned["permissionDecision"] = "allow"
                cleaned["updatedInput"] = {str(key): value for key, value in updated_input.items()}
            elif normalized == "allow":
                if (
                    response.get("policy_action") == "warn"
                    and isinstance(reason, str)
                    and reason.strip()
                    and not filtered.get("systemMessage")
                ):
                    filtered["systemMessage"] = reason
        filtered["hookSpecificOutput"] = cleaned
    return filtered


__all__ = ["codex_hook_response"]
