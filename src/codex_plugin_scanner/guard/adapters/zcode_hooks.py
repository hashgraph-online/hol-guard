"""z.ai ZCode hook payload and response helpers for HOL Guard.

ZCode speaks the same JSON stdin/stdout wire protocol as Claude Code: hook
events arrive as a JSON object on stdin, and Guard replies on stdout with a
``hookSpecificOutput.permissionDecision`` envelope. The current ZCode runtime
accepts ``permissionDecision`` values ``allow`` / ``ask`` / ``deny``:

* ``allow`` — the tool call proceeds.
* ``ask`` — ZCode opens its native permission prompt; the human decides.
* ``deny`` — the tool call is refused.

Guard maps its review tier (``review`` / ``require-reapproval``) to ``ask`` so
a human can approve through ZCode's own permission surface instead of every
review becoming a terminal denial. Hard denials (``block`` /
``sandbox-required``) and ``UserPromptSubmit`` blocks are emitted with exit
code ``2`` plus a human-readable reason on stderr, which ZCode treats as a
blocking error. ``ask`` responses must exit ``0`` because ZCode only parses
stdout JSON for successful hook processes.
"""

from __future__ import annotations

import json
import sys
from collections.abc import Mapping
from typing import TextIO

from .hook_payloads import normalize_session_and_workspace_aliases

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

# Review-tier actions become ZCode's ``ask`` so the native permission prompt
# (allow once / always / deny) can satisfy them; hard denials stay ``deny``.
_ZCODE_ASK_ACTIONS = frozenset({"review", "require-reapproval"})
_ZCODE_BLOCKING_ACTIONS = frozenset({"review", "require-reapproval", "sandbox-required", "block"})

# Reason text emitted by the native command control floor when the local
# authority is degraded, tampered, or pending recovery. ZCode sessions see
# this on every tool call until the control floor is restored, so the
# remediation command must travel with the message.
_AUTHORITY_BLOCK_REASON_MARKER = "native command extension policy"
_AUTHORITY_BLOCK_REMEDIATION = (
    " Run `hol-guard command controls acknowledge-degraded` after reviewing the "
    "degradation, or `hol-guard command controls recover-authority`, to restore the "
    "protected control floor."
)


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
        "posttoolusefailure": "PostToolUseFailure",
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

    normalize_session_and_workspace_aliases(normalized)

    prompt = normalized.get("prompt")
    if prompt is None and isinstance(normalized.get("userPrompt"), str):
        normalized["prompt"] = normalized["userPrompt"]
    return normalized


def _event_name_for_response(payload: Mapping[str, object]) -> str:
    raw_event = _raw_hook_event_name(payload)
    return _canonical_zcode_event_name(raw_event) if raw_event else "PreToolUse"


def zcode_authority_block_reason(reason: str) -> str:
    """Append the control-floor remediation hint to authority block reasons.

    ZCode surfaces the deny reason directly to the user; without the hint a
    degraded control floor reads as an unactionable brick on every tool call.
    """

    text = reason if isinstance(reason, str) else ""
    if _AUTHORITY_BLOCK_REASON_MARKER in text and "hol-guard command controls" not in text:
        return text + _AUTHORITY_BLOCK_REMEDIATION
    return text


def zcode_hook_response_from_guard(
    *,
    policy_action: str,
    reason: str,
    event_name: str | None = None,
) -> dict[str, object]:
    """Translate a Guard policy action into a ZCode-native stdout JSON response.

    ZCode understands the Claude Code hook response shape. Hard blocks emit a
    ``hookSpecificOutput`` envelope with ``permissionDecision: "deny"``; review
    tier actions emit ``permissionDecision: "ask"`` so ZCode routes the call to
    its native permission prompt instead of a terminal denial; everything else
    emits ``allow`` so ZCode continues normally.
    """

    resolved_event = event_name or "PreToolUse"
    if policy_action in _ZCODE_BLOCKING_ACTIONS:
        cleaned_reason = zcode_authority_block_reason(reason.strip() if isinstance(reason, str) else "") or (
            "Blocked by HOL Guard."
        )
        if resolved_event == "UserPromptSubmit":
            return {
                "decision": "block",
                "reason": cleaned_reason,
                "hookSpecificOutput": {
                    "hookEventName": resolved_event,
                    "additionalContext": cleaned_reason,
                },
            }
        permission_decision = "ask" if policy_action in _ZCODE_ASK_ACTIONS else "deny"
        return {
            "hookSpecificOutput": {
                "hookEventName": resolved_event,
                "permissionDecision": permission_decision,
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
    # stdout is the harness delivery channel; approval payloads must reach the operator.
    stream.write(json.dumps(response, separators=(",", ":")) + "\n")  # codeql[py/clear-text-logging-sensitive-data]
    stream.flush()


def zcode_hook_should_block(*, policy_action: str) -> bool:
    return policy_action in _ZCODE_BLOCKING_ACTIONS


def zcode_hook_process_exit(
    *,
    policy_action: str,
    event_name: str | None = None,
    payload: Mapping[str, object] | None = None,
) -> int:
    """Return the hook process exit code ZCode expects for a policy action.

    Exit code ``2`` makes ZCode treat the hook as a blocking error and deny the
    call outright, discarding stdout JSON. Review-tier PreToolUse decisions
    therefore must exit ``0`` so ZCode parses the ``permissionDecision: "ask"``
    envelope and opens its native permission prompt; the user, not the exit
    code, decides whether the action proceeds.
    """

    resolved_event = event_name
    if resolved_event is None and payload is not None:
        resolved_event = _event_name_for_response(payload)
    compact = (resolved_event or "PreToolUse").replace("_", "").replace("-", "").lower()
    if compact == "pretooluse" and policy_action in _ZCODE_ASK_ACTIONS:
        return 0
    return 2 if policy_action in _ZCODE_BLOCKING_ACTIONS else 0


__all__ = [
    "emit_zcode_hook_response",
    "prepare_zcode_hook_payload",
    "zcode_authority_block_reason",
    "zcode_hook_process_exit",
    "zcode_hook_response_from_guard",
    "zcode_hook_should_block",
]
