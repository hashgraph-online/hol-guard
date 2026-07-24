"""AdaL hook payload and response helpers for HOL Guard."""

from __future__ import annotations

import json
import sys
from collections.abc import Mapping
from typing import TextIO

_BLOCKING_ACTIONS = frozenset({"review", "require-reapproval", "sandbox-required", "block"})
_BLOCKING_EVENTS = frozenset({"PreToolUse", "UserPromptSubmit"})
_ADAL_TOOL_ALIASES: dict[str, str] = {
    "bash": "Bash",
    "read_file": "Read",
    "read_image": "Read",
    "write_file": "Write",
    "create_file": "Write",
    "rewrite_file": "Write",
    "replace_by_string": "Edit",
    "delete_lines": "Edit",
    "grep": "Grep",
    "glob": "Glob",
    "fetch_url": "WebFetch",
    "web_search": "WebSearch",
}


def _raw_hook_event_name(payload: Mapping[str, object]) -> str:
    for key in ("hook_event_name", "hookEventName"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def _canonical_adal_event_name(raw_event: str) -> str:
    normalized = raw_event.replace("_", "").replace("-", "").lower()
    mapping = {
        "pretooluse": "PreToolUse",
        "posttooluse": "PostToolUse",
        "posttoolusefailure": "PostToolUseFailure",
        "userpromptsubmit": "UserPromptSubmit",
        "permissionrequest": "PermissionRequest",
        "stop": "Stop",
    }
    return mapping.get(normalized, raw_event or "PreToolUse")


def _canonical_adal_tool_name(raw_tool: object | None) -> str | None:
    if not isinstance(raw_tool, str) or not raw_tool.strip():
        return None
    stripped = raw_tool.strip()
    return _ADAL_TOOL_ALIASES.get(stripped.lower(), stripped)


def _normalized_tool_input(raw_tool: object | None, value: object | None) -> object | None:
    if not isinstance(value, Mapping):
        return value
    normalized = dict(value)
    raw_name = raw_tool.strip().lower() if isinstance(raw_tool, str) else ""
    if raw_name in {"create_file", "rewrite_file"}:
        content = normalized.get("new_string")
        if "content" not in normalized and isinstance(content, str):
            normalized["content"] = content
    return normalized


def prepare_adal_hook_payload(payload: Mapping[str, object]) -> dict[str, object]:
    """Map AdaL's stdin JSON object onto Guard's shared hook shape."""

    normalized = dict(payload)
    raw_event = _raw_hook_event_name(normalized)
    if raw_event:
        normalized["hook_event_name"] = _canonical_adal_event_name(raw_event)

    raw_tool = normalized.get("tool_name")
    if raw_tool is None:
        raw_tool = normalized.get("toolName")
    canonical_tool = _canonical_adal_tool_name(raw_tool)
    if canonical_tool is not None:
        normalized["tool_name"] = canonical_tool

    tool_input = normalized.get("tool_input")
    if tool_input is None:
        tool_input = normalized.get("toolInput")
    if tool_input is None:
        tool_input = normalized.get("arguments")
    if tool_input is not None:
        normalized["tool_input"] = _normalized_tool_input(raw_tool, tool_input)

    session_id = normalized.get("session_id")
    if session_id is None and isinstance(normalized.get("sessionId"), str):
        normalized["session_id"] = normalized["sessionId"]

    workspace_root = normalized.get("workspace_root")
    if workspace_root is None and isinstance(normalized.get("workspaceRoot"), str):
        normalized["workspace_root"] = normalized["workspaceRoot"]
    if workspace_root is None and isinstance(normalized.get("cwd"), str):
        normalized["workspace_root"] = normalized["cwd"]
    return normalized


def adal_hook_should_block(*, policy_action: str, event_name: str) -> bool:
    """Return whether AdaL can enforce this Guard action at this event."""

    return policy_action in _BLOCKING_ACTIONS and event_name in _BLOCKING_EVENTS


def adal_hook_response_from_guard(
    *,
    policy_action: str,
    reason: str,
    event_name: str | None = None,
) -> dict[str, object]:
    """Translate a Guard action into AdaL's hook stdout protocol."""

    resolved_event = _canonical_adal_event_name(event_name or "PreToolUse")
    cleaned_reason = (reason.strip() if isinstance(reason, str) else "") or "Blocked by HOL Guard."
    if adal_hook_should_block(policy_action=policy_action, event_name=resolved_event):
        if resolved_event == "UserPromptSubmit":
            return {
                "decision": "block",
                "reason": cleaned_reason,
                "hookSpecificOutput": {
                    "hookEventName": resolved_event,
                    "additionalContext": cleaned_reason,
                },
            }
        return {
            "hookSpecificOutput": {
                "hookEventName": resolved_event,
                "permissionDecision": "deny",
                "permissionDecisionReason": cleaned_reason,
            }
        }
    return {"hookSpecificOutput": {"hookEventName": resolved_event}}


def emit_adal_hook_response(
    *,
    policy_action: str,
    reason: str,
    event_name: str | None = None,
    payload: Mapping[str, object] | None = None,
    output_stream: TextIO | None = None,
) -> None:
    resolved_event = event_name
    if resolved_event is None and payload is not None:
        raw_event = _raw_hook_event_name(payload)
        resolved_event = _canonical_adal_event_name(raw_event) if raw_event else "PreToolUse"
    response = adal_hook_response_from_guard(
        policy_action=policy_action,
        reason=reason,
        event_name=resolved_event,
    )
    stream = output_stream if output_stream is not None else sys.stdout
    stream.write(json.dumps(response, separators=(",", ":")) + "\n")
    stream.flush()


__all__ = [
    "adal_hook_response_from_guard",
    "adal_hook_should_block",
    "emit_adal_hook_response",
    "prepare_adal_hook_payload",
]
