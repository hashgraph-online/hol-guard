"""Devin CLI hook payload and response helpers for HOL Guard.

Devin speaks the same JSON stdin/stdout wire protocol as Claude Code: hook
events arrive as a JSON object on stdin, and Guard replies on stdout with a
``{"decision": "block", "reason": ...}`` object (paired with exit code ``2``)
or a ``hookSpecificOutput`` envelope. Devin also honors a
``{"decision": "approve"}`` response, which Guard must never emit, so allow
responses carry only the event envelope with no decision keys.
"""

from __future__ import annotations

import json
import os
import sys
from collections.abc import Mapping
from typing import TextIO

from .hook_payloads import normalize_session_and_workspace_aliases

# Devin's tool names map onto the Claude-Code-shaped canonical names the Guard
# runtime contract expects. ``apply_patch`` already matches the canonical
# contract; interactive shell helpers (write_to_process, get_output,
# kill_shell) are deliberately unmapped because they carry no new command.
_DEVIN_TOOL_ALIASES: dict[str, str] = {
    "exec": "Bash",
    "read": "Read",
    "notebook_read": "Read",
    "write": "Write",
    "edit": "Edit",
    "notebook_edit": "Edit",
    "webfetch": "WebFetch",
    "grep": "Grep",
    "glob": "Glob",
}

_DEVIN_PROJECT_DIR_ENV = "DEVIN_PROJECT_DIR"


def _raw_hook_event_name(payload: Mapping[str, object]) -> str:
    for key in ("hook_event_name", "hookEventName"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip().lower()
    return ""


def _canonical_devin_event_name(raw_event: str) -> str:
    normalized = raw_event.replace("_", "").replace("-", "").lower()
    mapping = {
        "pretooluse": "PreToolUse",
        "userpromptsubmit": "UserPromptSubmit",
        "posttooluse": "PostToolUse",
        "permissionrequest": "PermissionRequest",
        "postcompaction": "PostCompaction",
        "sessionstart": "SessionStart",
        "sessionend": "SessionEnd",
        "notification": "Notification",
        "stop": "Stop",
    }
    return mapping.get(normalized, raw_event or "PreToolUse")


def _canonical_devin_tool_name(raw_tool: object | None) -> str | None:
    if not isinstance(raw_tool, str) or not raw_tool.strip():
        return None
    stripped = raw_tool.strip()
    return _DEVIN_TOOL_ALIASES.get(stripped.lower(), stripped)


def _apply_devin_mcp_call(normalized: dict[str, object]) -> None:
    """Rewrite ``mcp_call_tool`` dispatch payloads onto the ``mcp__*`` shape.

    The Guard runtime evaluates MCP tools by their ``mcp__<server>__<tool>``
    name, so the dispatcher's ``server_name``/``tool_name`` inputs are folded
    into the canonical tool name and ``arguments`` becomes the tool input.
    The original routing pair is preserved under ``devin_mcp_call`` for
    evidence.
    """

    if str(normalized.get("tool_name") or "").strip().lower() != "mcp_call_tool":
        return
    tool_input = normalized.get("tool_input")
    if not isinstance(tool_input, dict):
        return
    server_name = tool_input.get("server_name")
    tool_name = tool_input.get("tool_name")
    if not isinstance(server_name, str) or not server_name.strip():
        return
    if not isinstance(tool_name, str) or not tool_name.strip():
        return
    normalized["devin_mcp_call"] = {"server_name": server_name, "tool_name": tool_name}
    normalized["tool_name"] = f"mcp__{server_name.strip()}__{tool_name.strip()}"
    arguments = tool_input.get("arguments")
    normalized["tool_input"] = dict(arguments) if isinstance(arguments, dict) else {}


def prepare_devin_hook_payload(payload: Mapping[str, object]) -> dict[str, object]:
    """Map a Devin hook stdin JSON object onto Guard's shared hook shape."""

    normalized = dict(payload)
    raw_event = _raw_hook_event_name(normalized)
    if raw_event:
        normalized["hook_event_name"] = _canonical_devin_event_name(raw_event)

    tool_name = normalized.get("tool_name")
    if tool_name is None:
        tool_name = normalized.get("toolName")
    canonical_tool = _canonical_devin_tool_name(tool_name)
    if canonical_tool is not None:
        normalized["tool_name"] = canonical_tool

    tool_input = normalized.get("tool_input")
    if tool_input is None:
        tool_input = normalized.get("toolInput")
    if tool_input is None:
        tool_input = normalized.get("arguments")
    if tool_input is not None:
        normalized["tool_input"] = tool_input

    _apply_devin_mcp_call(normalized)

    # Devin hook payloads carry no cwd; DEVIN_PROJECT_DIR is the only
    # workspace signal the harness exports to hook processes.
    if normalized.get("cwd") is None and normalized.get("workspace") is None:
        project_dir = os.environ.get(_DEVIN_PROJECT_DIR_ENV)
        if isinstance(project_dir, str) and project_dir.strip():
            normalized["cwd"] = project_dir.strip()

    normalize_session_and_workspace_aliases(normalized)

    prompt = normalized.get("prompt")
    if prompt is None and isinstance(normalized.get("userPrompt"), str):
        normalized["prompt"] = normalized["userPrompt"]
    return normalized


def _event_name_for_response(payload: Mapping[str, object]) -> str:
    raw_event = _raw_hook_event_name(payload)
    return _canonical_devin_event_name(raw_event) if raw_event else "PreToolUse"


def devin_hook_response_from_guard(
    *,
    policy_action: str,
    reason: str,
    event_name: str | None = None,
) -> dict[str, object]:
    """Translate a Guard policy action into a Devin-native stdout JSON response.

    Blocking actions emit a top-level ``decision: "block"`` (which Devin
    treats the same as exit code ``2``) plus a ``permissionDecision: "deny"``
    envelope for tool events, or an ``additionalContext`` envelope for
    ``UserPromptSubmit``. Non-blocking actions emit only the event envelope:
    Devin's ``decision: "approve"`` auto-approve response must never come
    from Guard.
    """

    resolved_event = event_name or "PreToolUse"
    if policy_action in {"review", "require-reapproval", "sandbox-required", "block"}:
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
            "decision": "block",
            "reason": cleaned_reason,
            "hookSpecificOutput": {
                "hookEventName": resolved_event,
                "permissionDecision": "deny",
                "permissionDecisionReason": cleaned_reason,
            },
        }
    return {"hookSpecificOutput": {"hookEventName": resolved_event}}


def emit_devin_hook_response(
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
    response = devin_hook_response_from_guard(
        policy_action=policy_action,
        reason=reason,
        event_name=resolved_event,
    )
    stream = output_stream if output_stream is not None else sys.stdout
    stream.write(json.dumps(response, separators=(",", ":")) + "\n")
    stream.flush()


def devin_hook_should_block(*, policy_action: str) -> bool:
    return policy_action in {"review", "require-reapproval", "sandbox-required", "block"}


__all__ = [
    "devin_hook_response_from_guard",
    "devin_hook_should_block",
    "emit_devin_hook_response",
    "prepare_devin_hook_payload",
]
