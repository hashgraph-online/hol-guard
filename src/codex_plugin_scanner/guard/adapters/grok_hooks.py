"""Grok Build CLI hook payload and response helpers for HOL Guard."""

from __future__ import annotations

import json
import os
import sys
from collections.abc import Mapping
from typing import TextIO

from .grok_approval_resume import grok_resume_metadata_from_guard_payload

_GROK_TOOL_ALIASES: dict[str, str] = {
    "run_terminal_command": "Bash",
    "read_file": "Read",
    "search_replace": "Edit",
    "write": "Edit",
    "write_file": "Edit",
    "multi_edit": "Edit",
    "multiedit": "Edit",
    "grep": "Grep",
    "glob": "Grep",
    "list_dir": "Read",
    "listdir": "Read",
    "web_fetch": "WebFetch",
    "web_search": "WebFetch",
    "open_page": "WebFetch",
    "open_page_with_find": "WebFetch",
    "spawn_subagent": "Task",
    "task": "Task",
    "use_tool": "MCPTool",
    "callmcptool": "MCPTool",
}

_GROK_EVENT_NAMES: dict[str, str] = {
    "pretooluse": "PreToolUse",
    "userpromptsubmit": "UserPromptSubmit",
    "posttooluse": "PostToolUse",
    "posttoolusefailure": "PostToolUse",
    "sessionstart": "SessionStart",
    "sessionend": "SessionEnd",
    "stop": "Stop",
    "subagentstart": "SubagentStart",
    "subagentstop": "SubagentStop",
    "subagentend": "SubagentStop",
    "permissiondenied": "PermissionDenied",
}

# Grok treats these events as observe-only. A deny JSON is ignored, so Guard
# must not claim they are an enforcement boundary.
_OBSERVE_ONLY_EVENTS = frozenset(
    {
        "UserPromptSubmit",
        "SessionStart",
        "SessionEnd",
        "SubagentStart",
        "SubagentStop",
        "PostToolUse",
        "PermissionDenied",
    }
)


def _raw_hook_event_name(payload: Mapping[str, object]) -> str:
    for key in ("hook_event_name", "hookEventName"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip().lower()
    return ""


def _canonical_grok_event_name(raw_event: str) -> str:
    normalized = raw_event.replace("_", "").replace("-", "").lower()
    return _GROK_EVENT_NAMES.get(normalized, raw_event or "PreToolUse")


def _is_observe_only_event(event_name: str | None) -> bool:
    if not isinstance(event_name, str) or not event_name.strip():
        return False
    return _canonical_grok_event_name(event_name.strip()) in _OBSERVE_ONLY_EVENTS


def _canonical_grok_tool_name(raw_tool: object | None) -> str | None:
    if not isinstance(raw_tool, str) or not raw_tool.strip():
        return None
    stripped = raw_tool.strip()
    return _GROK_TOOL_ALIASES.get(stripped.lower(), stripped)


def _mapping_value(value: object) -> Mapping[str, object] | None:
    return value if isinstance(value, Mapping) else None


def _native_mcp_envelope(tool_input: Mapping[str, object]) -> bool:
    server = tool_input.get("server")
    tool = tool_input.get("tool")
    return isinstance(server, str) and bool(server.strip()) and isinstance(tool, str) and bool(tool.strip())


def _unwrap_dispatcher_tool(
    tool_name: str | None,
    tool_input: Mapping[str, object] | None,
) -> tuple[str | None, Mapping[str, object] | None]:
    if tool_name != "MCPTool" or tool_input is None:
        return tool_name, tool_input
    # Grok's native MCP payload keeps the method name in `tool` next to `server`.
    # That is not a dispatcher wrapper and must stay MCPTool.
    if _native_mcp_envelope(tool_input):
        return tool_name, tool_input
    for key in ("tool_name", "toolName", "name", "tool"):
        inner = tool_input.get(key)
        if isinstance(inner, str) and inner.strip() and inner.strip() != "MCPTool":
            inner_input = _mapping_value(tool_input.get("arguments") or tool_input.get("toolInput"))
            return inner.strip(), inner_input or tool_input
    return tool_name, tool_input


def _apply_qualified_mcp_tool(normalized: dict[str, object], tool_name: str) -> str:
    if "__" not in tool_name or tool_name.lower() in _GROK_TOOL_ALIASES:
        return tool_name
    server, tool = tool_name.split("__", 1)
    if not server or not tool:
        return tool_name
    normalized["mcp_server"] = server
    normalized["mcp_tool"] = tool
    normalized["original_tool_name"] = tool_name
    return "MCPTool"


def prepare_grok_hook_payload(payload: Mapping[str, object]) -> dict[str, object]:
    """Map Grok hook stdin JSON into Guard hook normalization shape."""

    normalized = dict(payload)
    raw_event = _raw_hook_event_name(normalized)
    if raw_event:
        normalized["hook_event_name"] = _canonical_grok_event_name(raw_event)
    tool_name = normalized.get("tool_name")
    if tool_name is None:
        tool_name = normalized.get("toolName")
    tool_input = normalized.get("tool_input")
    if tool_input is None:
        tool_input = normalized.get("toolInput")
    mapped_input = _mapping_value(tool_input)
    canonical_tool = _canonical_grok_tool_name(tool_name)
    canonical_tool, mapped_input = _unwrap_dispatcher_tool(canonical_tool, mapped_input)
    if isinstance(canonical_tool, str):
        remapped = _canonical_grok_tool_name(canonical_tool)
        if remapped is not None:
            canonical_tool = remapped
        canonical_tool = _apply_qualified_mcp_tool(normalized, canonical_tool)
        normalized["tool_name"] = canonical_tool
    if mapped_input is not None:
        if canonical_tool == "MCPTool" and _native_mcp_envelope(mapped_input):
            normalized.setdefault("mcp_server", str(mapped_input["server"]).strip())
            normalized.setdefault("mcp_tool", str(mapped_input["tool"]).strip())
        normalized["tool_input"] = dict(mapped_input)
        tool_input = mapped_input
    elif tool_input is not None:
        normalized["tool_input"] = tool_input
    session_id = normalized.get("session_id")
    if session_id is None and isinstance(normalized.get("sessionId"), str):
        normalized["session_id"] = normalized["sessionId"]
    workspace_root = normalized.get("workspace_root")
    if workspace_root is None and isinstance(normalized.get("workspaceRoot"), str):
        normalized["workspace_root"] = normalized["workspaceRoot"]
    if workspace_root is None and isinstance(normalized.get("cwd"), str):
        normalized["workspace_root"] = normalized["cwd"]
    if isinstance(normalized.get("permissionMode"), str) and "permission_mode" not in normalized:
        normalized["permission_mode"] = normalized["permissionMode"]
    if isinstance(normalized.get("subagentType"), str) and "subagent_type" not in normalized:
        normalized["subagent_type"] = normalized["subagentType"]
    prompt = normalized.get("prompt")
    if prompt is None and isinstance(normalized.get("userPrompt"), str):
        normalized["prompt"] = normalized["userPrompt"]
    if (
        prompt is None
        and canonical_tool == "Task"
        and isinstance(tool_input, Mapping)
        and isinstance(tool_input.get("prompt"), str)
    ):
        normalized["prompt"] = tool_input["prompt"]
    if canonical_tool == "Task" and isinstance(tool_input, Mapping):
        subagent_type = tool_input.get("subagent_type") or tool_input.get("subagentType")
        if isinstance(subagent_type, str) and subagent_type.strip():
            normalized["subagent_type"] = subagent_type.strip()
    return normalized


def grok_hook_response_from_guard(
    *,
    policy_action: str,
    reason: str,
    event_name: str | None = None,
    approval_payload: Mapping[str, object] | None = None,
) -> dict[str, object]:
    """Translate Guard policy action into Grok hook stdout JSON."""

    if _is_observe_only_event(event_name):
        return {"decision": "allow"}
    if policy_action in {"review", "require-reapproval", "sandbox-required", "block"}:
        cleaned_reason = _dedupe_grok_block_reason(reason.strip() if isinstance(reason, str) else "")
        response: dict[str, object] = {
            "decision": "deny",
            "reason": cleaned_reason or "Blocked by HOL Guard.",
        }
        response.update(grok_resume_metadata_from_guard_payload(approval_payload))
        return response
    return {"decision": "allow"}


def _dedupe_grok_block_reason(reason: str) -> str:
    if not reason:
        return reason
    marker = "Open HOL Guard to approve or keep this blocked:"
    first = reason.find(marker)
    if first == -1:
        return reason
    second = reason.find(marker, first + len(marker))
    if second == -1:
        return reason
    return reason[:second].rstrip()


_last_grok_policy_action = ""


def emit_grok_hook_response(
    *,
    policy_action: str,
    reason: str,
    event_name: str | None = None,
    approval_payload: Mapping[str, object] | None = None,
    output_stream: TextIO | None = None,
) -> None:
    global _last_grok_policy_action
    live_action, live_reason, live_payload = _apply_live_approval_wait(
        policy_action=policy_action,
        reason=reason,
        event_name=event_name,
        approval_payload=approval_payload,
    )
    payload = grok_hook_response_from_guard(
        policy_action=live_action,
        reason=live_reason,
        event_name=event_name,
        approval_payload=live_payload,
    )
    _last_grok_policy_action = "allow" if payload.get("decision") == "allow" else live_action
    stream = output_stream if output_stream is not None else sys.stdout
    stream.write(json.dumps(payload, separators=(",", ":")) + "\n")
    stream.flush()


def grok_hook_process_exit(policy_action: str) -> int:
    if _last_grok_policy_action == "allow":
        return 0
    return 0 if policy_action not in {"review", "require-reapproval", "sandbox-required", "block"} else 2


def _apply_live_approval_wait(
    *,
    policy_action: str,
    reason: str,
    event_name: str | None,
    approval_payload: Mapping[str, object] | None,
) -> tuple[str, str, Mapping[str, object] | None]:
    if policy_action not in {"review", "require-reapproval"} or not isinstance(approval_payload, Mapping):
        return policy_action, reason, approval_payload
    store = _guard_store_from_argv()
    if store is None:
        return policy_action, reason, approval_payload
    from ..config import load_guard_config
    from .grok_approval_resume import wait_for_grok_live_approval

    response_payload = dict(approval_payload)
    decision = wait_for_grok_live_approval(
        event_name=event_name or "",
        policy_action=policy_action,
        response_payload=response_payload,
        store=store,
        timeout_seconds=load_guard_config(store.guard_home).approval_wait_timeout_seconds,
        json_mode="--json" in sys.argv,
        payload=response_payload,
    )
    if decision == "allow":
        return "allow", "", response_payload
    if decision == "block":
        return "block", reason, response_payload
    return policy_action, reason, response_payload


def _guard_store_from_argv():
    home_value = None
    if "--guard-home" in sys.argv:
        index = sys.argv.index("--guard-home")
        if index + 1 < len(sys.argv):
            home_value = sys.argv[index + 1]
    if not home_value:
        home_value = os.environ.get("HOL_GUARD_HOME")
    if not home_value:
        return None
    from pathlib import Path

    from ..store import GuardStore

    return GuardStore(Path(home_value))


def grok_hook_should_block(*, policy_action: str, event_name: str | None = None) -> bool:
    if _is_observe_only_event(event_name):
        return False
    return policy_action in {"review", "require-reapproval", "sandbox-required", "block"}


__all__ = [
    "emit_grok_hook_response",
    "grok_hook_process_exit",
    "grok_hook_response_from_guard",
    "grok_hook_should_block",
    "prepare_grok_hook_payload",
]
