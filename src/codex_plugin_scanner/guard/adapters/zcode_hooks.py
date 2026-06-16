"""z.ai ZCode hook payload and response helpers for HOL Guard.

ZCode speaks the same JSON stdin/stdout wire protocol as Claude Code: hook
events arrive as a JSON object on stdin, and Guard replies on stdout with a
``hookSpecificOutput.permissionDecision`` envelope (``allow`` / ``deny``) or,
for ``UserPromptSubmit`` blocks, a top-level ``decision`` object. Block
responses are paired with exit code ``2`` and a human-readable reason on
stderr by the generic hook emitter.
"""

from __future__ import annotations

import json
import sys
from collections.abc import Mapping
from typing import TextIO

# ZCode surfaces tools using Claude Code names (Bash, Read, Write, Edit, ...) and
# MCP tools as ``mcp__<server>__<tool>``. No alias table is needed because the
# canonical tool name already matches the Guard runtime contract.
_ZCODE_TOOL_ALIASES: dict[str, str] = {
    "run_terminal_command": "Bash",
    "run_command": "Bash",
    "read_file": "Read",
    "write_file": "Write",
    "search_replace": "Edit",
    "multi_edit": "MultiEdit",
    "grep": "Grep",
    "web_fetch": "WebFetch",
    "web_search": "WebSearch",
}


def _raw_hook_event_name(payload: Mapping[str, object]) -> str:
    for key in ("hook_event_name", "hookEventName"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip().lower()
    return ""


def _canonical_zcode_event_name(raw_event: str) -> str:
    normalized = raw_event.replace("_", "").replace("-", "").lower()
    mapping = {
        "pretooluse": "PreToolUse",
        "userpromptsubmit": "UserPromptSubmit",
        "posttooluse": "PostToolUse",
        "sessionstart": "SessionStart",
        "notification": "Notification",
        "permissionrequest": "PermissionRequest",
        "stop": "Stop",
    }
    return mapping.get(normalized, raw_event or "PreToolUse")


def _canonical_zcode_tool_name(raw_tool: object | None) -> str | None:
    if not isinstance(raw_tool, str) or not raw_tool.strip():
        return None
    stripped = raw_tool.strip()
    return _ZCODE_TOOL_ALIASES.get(stripped.lower(), stripped)


def prepare_zcode_hook_payload(payload: Mapping[str, object]) -> dict[str, object]:
    """Map a ZCode hook stdin JSON object onto Guard's shared hook shape."""

    normalized = dict(payload)
    raw_event = _raw_hook_event_name(normalized)
    if raw_event:
        normalized["hook_event_name"] = _canonical_zcode_event_name(raw_event)

    tool_name = normalized.get("tool_name")
    if tool_name is None:
        tool_name = normalized.get("toolName")
    canonical_tool = _canonical_zcode_tool_name(tool_name)
    if canonical_tool is not None:
        normalized["tool_name"] = canonical_tool

    tool_input = normalized.get("tool_input")
    if tool_input is None:
        tool_input = normalized.get("toolInput")
    if tool_input is None:
        tool_input = normalized.get("arguments")
    if tool_input is not None:
        normalized["tool_input"] = tool_input

    session_id = normalized.get("session_id")
    if session_id is None and isinstance(normalized.get("sessionId"), str):
        normalized["session_id"] = normalized["sessionId"]

    workspace_root = normalized.get("workspace_root")
    if workspace_root is None and isinstance(normalized.get("workspaceRoot"), str):
        normalized["workspace_root"] = normalized["workspaceRoot"]
    if workspace_root is None and isinstance(normalized.get("cwd"), str):
        normalized["workspace_root"] = normalized["cwd"]

    prompt = normalized.get("prompt")
    if prompt is None and isinstance(normalized.get("userPrompt"), str):
        normalized["prompt"] = normalized["userPrompt"]
    return normalized


def _event_name_for_response(payload: Mapping[str, object]) -> str:
    raw_event = _raw_hook_event_name(payload)
    return _canonical_zcode_event_name(raw_event) if raw_event else "PreToolUse"


def zcode_hook_response_from_guard(
    *,
    policy_action: str,
    reason: str,
    event_name: str | None = None,
) -> dict[str, object]:
    """Translate a Guard policy action into a ZCode-native stdout JSON response.

    ZCode understands the Claude Code hook response shape. For blocking policy
    actions we emit a ``hookSpecificOutput`` envelope with
    ``permissionDecision: "deny"``; otherwise we emit ``allow`` so ZCode
    continues normally.
    """

    resolved_event = event_name or "PreToolUse"
    if policy_action in {"block", "sandbox-required", "require-reapproval"}:
        cleaned_reason = (reason.strip() if isinstance(reason, str) else "") or "Blocked by HOL Guard."
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
    if resolved_event == "UserPromptSubmit":
        return {"hookSpecificOutput": {"hookEventName": resolved_event}}
    return {"hookSpecificOutput": {"hookEventName": resolved_event, "permissionDecision": "allow"}}


def emit_zcode_hook_response(
    *,
    policy_action: str,
    reason: str,
    event_name: str | None = None,
    payload: Mapping[str, object] | None = None,
    output_stream: TextIO | None = None,
) -> None:
    resolved_event = event_name
    if resolved_event is None and payload is not None:
        resolved_event = _event_name_for_response(payload)
    response = zcode_hook_response_from_guard(
        policy_action=policy_action,
        reason=reason,
        event_name=resolved_event,
    )
    stream = output_stream if output_stream is not None else sys.stdout
    stream.write(json.dumps(response, separators=(",", ":")) + "\n")
    stream.flush()


def zcode_hook_should_block(*, policy_action: str) -> bool:
    return policy_action in {"block", "sandbox-required", "require-reapproval"}


__all__ = [
    "emit_zcode_hook_response",
    "prepare_zcode_hook_payload",
    "zcode_hook_response_from_guard",
    "zcode_hook_should_block",
]
