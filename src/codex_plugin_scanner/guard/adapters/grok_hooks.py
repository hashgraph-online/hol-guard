"""Grok Build CLI hook payload and response helpers for HOL Guard."""

from __future__ import annotations

import json
import sys
from collections.abc import Mapping
from typing import TextIO

_GROK_TOOL_ALIASES: dict[str, str] = {
    "run_terminal_command": "Bash",
    "read_file": "Read",
    "search_replace": "Edit",
    "write": "Edit",
    "grep": "Grep",
    "web_fetch": "WebFetch",
    "web_search": "WebFetch",
}


def _raw_hook_event_name(payload: Mapping[str, object]) -> str:
    for key in ("hook_event_name", "hookEventName"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip().lower()
    return ""


def _canonical_grok_event_name(raw_event: str) -> str:
    normalized = raw_event.replace("_", "").replace("-", "").lower()
    mapping = {
        "pretooluse": "PreToolUse",
        "userpromptsubmit": "UserPromptSubmit",
        "posttooluse": "PostToolUse",
        "sessionstart": "SessionStart",
        "stop": "Stop",
    }
    return mapping.get(normalized, raw_event or "PreToolUse")


def _canonical_grok_tool_name(raw_tool: object | None) -> str | None:
    if not isinstance(raw_tool, str) or not raw_tool.strip():
        return None
    stripped = raw_tool.strip()
    lowered = stripped.lower()
    return _GROK_TOOL_ALIASES.get(lowered, stripped)


def prepare_grok_hook_payload(payload: Mapping[str, object]) -> dict[str, object]:
    """Map Grok hook stdin JSON into Guard hook normalization shape."""

    normalized = dict(payload)
    raw_event = _raw_hook_event_name(normalized)
    if raw_event:
        normalized["hook_event_name"] = _canonical_grok_event_name(raw_event)
    tool_name = normalized.get("tool_name")
    if tool_name is None:
        tool_name = normalized.get("toolName")
    canonical_tool = _canonical_grok_tool_name(tool_name)
    if canonical_tool is not None:
        normalized["tool_name"] = canonical_tool
    tool_input = normalized.get("tool_input")
    if tool_input is None:
        tool_input = normalized.get("toolInput")
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


def grok_hook_response_from_guard(*, policy_action: str, reason: str) -> dict[str, object]:
    """Translate Guard policy action into Grok PreToolUse stdout JSON."""

    if policy_action in {"block", "sandbox-required", "require-reapproval"}:
        cleaned_reason = reason.strip() if isinstance(reason, str) else "Blocked by HOL Guard."
        return {"decision": "deny", "reason": cleaned_reason or "Blocked by HOL Guard."}
    return {"decision": "allow"}


def emit_grok_hook_response(
    *,
    policy_action: str,
    reason: str,
    output_stream: TextIO | None = None,
) -> None:
    payload = grok_hook_response_from_guard(policy_action=policy_action, reason=reason)
    stream = output_stream if output_stream is not None else sys.stdout
    stream.write(json.dumps(payload, separators=(",", ":")) + "\n")
    stream.flush()


def grok_hook_should_block(*, policy_action: str) -> bool:
    return policy_action in {"block", "sandbox-required", "require-reapproval"}


__all__ = [
    "emit_grok_hook_response",
    "grok_hook_response_from_guard",
    "grok_hook_should_block",
    "prepare_grok_hook_payload",
]
