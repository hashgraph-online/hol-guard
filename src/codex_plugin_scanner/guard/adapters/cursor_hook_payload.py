"""Cursor hook payload normalization and response mapping."""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path

from ..action_lattice import is_guard_action


def _infer_cursor_hook_event_name(payload: Mapping[str, object]) -> dict[str, object]:
    normalized = dict(payload)
    if _raw_hook_event_name(normalized):
        return normalized
    file_path = normalized.get("file_path")
    if isinstance(file_path, str) and file_path.strip():
        normalized["hook_event_name"] = "beforeReadFile"
        return normalized
    command = normalized.get("command")
    if isinstance(command, str) and command.strip():
        normalized["hook_event_name"] = "beforeShellExecution"
        return normalized
    if normalized.get("tool_name") is not None or normalized.get("tool_input") is not None:
        normalized["hook_event_name"] = "preToolUse"
    return normalized


# Payload normalizers below are mirrored inside _HOOK_SCRIPT_TEMPLATE for the installed
# Cursor hook script. Keep both copies in sync when changing observer or MCP behavior.


def _cursor_shell_hook_payload(normalized: dict[str, object], *, hook_event_name: str) -> dict[str, object]:
    payload = dict(normalized)
    payload["hook_event_name"] = hook_event_name
    payload.setdefault("tool_name", "Shell")
    tool_input = _tool_input_dict(payload.get("tool_input"))
    command = payload.get("command")
    if isinstance(command, str) and command.strip():
        tool_input.setdefault("command", command.strip())
    cwd = payload.get("cwd")
    if isinstance(cwd, str) and cwd.strip():
        tool_input.setdefault("working_directory", cwd.strip())
    payload["tool_input"] = tool_input
    return payload


def _cursor_mcp_hook_payload(normalized: dict[str, object], *, hook_event_name: str) -> dict[str, object]:
    payload = dict(normalized)
    payload["hook_event_name"] = hook_event_name
    tool_input = _tool_input_dict(payload.get("tool_input"))
    payload["tool_input"] = tool_input
    tool_name = payload.get("tool_name")
    if isinstance(tool_name, str) and tool_name.strip():
        payload["tool_name"] = tool_name.strip()
    else:
        payload.setdefault("tool_name", "MCP")
    return payload


def prepare_cursor_hook_payload(payload: Mapping[str, object]) -> dict[str, object]:
    """Map Cursor hook stdin JSON into Guard hook normalization shape."""

    normalized = _infer_cursor_hook_event_name(payload)
    raw_event = _raw_hook_event_name(normalized)
    if raw_event == "aftershellexecution":
        return _cursor_shell_hook_payload(normalized, hook_event_name="afterShellExecution")
    if raw_event == "aftermcpexecution":
        return _cursor_mcp_hook_payload(normalized, hook_event_name="afterMCPExecution")
    if raw_event == "beforeshellexecution":
        prepared = _cursor_shell_hook_payload(normalized, hook_event_name="PreToolUse")
        prepared["cursor_source_hook_event"] = "beforeShellExecution"
        return prepared
    if raw_event == "beforemcpexecution":
        prepared = _cursor_mcp_hook_payload(normalized, hook_event_name="PreToolUse")
        tool_input = _tool_input_dict(prepared.get("tool_input"))
        for key in ("url", "command"):
            value = normalized.get(key)
            if isinstance(value, str) and value.strip():
                tool_input.setdefault(key, value.strip())
        prepared["tool_input"] = tool_input
        prepared["cursor_source_hook_event"] = "beforeMCPExecution"
        return prepared
    if raw_event == "beforereadfile":
        normalized["hook_event_name"] = "PreToolUse"
        normalized.setdefault("tool_name", "Read")
        tool_input = _tool_input_dict(normalized.get("tool_input"))
        file_path = normalized.get("file_path")
        if isinstance(file_path, str) and file_path.strip():
            tool_input.setdefault("file_path", file_path.strip())
            tool_input.setdefault("path", file_path.strip())
        normalized["tool_input"] = tool_input
        return normalized
    if raw_event == "pretooluse":
        normalized["hook_event_name"] = "PreToolUse"
    return normalized


def _validated_hol_guard_src_path(path_str: str) -> str | None:
    """Accept only directories that look like a hol-guard source tree."""

    try:
        if not isinstance(path_str, str) or not path_str.strip():
            return None
        candidate = Path(path_str.strip()).expanduser().resolve()
    except (OSError, RuntimeError, ValueError, TypeError):
        return None
    if not candidate.is_dir():
        return None
    if not (candidate / "codex_plugin_scanner").is_dir():
        return None
    return str(candidate)


def cursor_hook_would_prompt_user(
    *,
    policy_action: str,
    guard_payload: Mapping[str, object] | None = None,
) -> bool:
    """Return True when Guard maps this hook result to Cursor permission ask."""

    del guard_payload
    return policy_action in {"require-reapproval", "review"}


def cursor_hook_requires_approval_center_queue(
    *,
    policy_action: str,
    guard_payload: Mapping[str, object] | None = None,
) -> bool:
    """Return True when Cursor native prompts should also appear in the approval center.

    Currently equivalent to ``cursor_hook_would_prompt_user``; kept separate so the
    two concepts can diverge without touching call sites.
    """

    return cursor_hook_would_prompt_user(
        policy_action=policy_action,
        guard_payload=guard_payload,
    )


def cursor_hook_response_from_guard(
    *,
    policy_action: str,
    guard_payload: Mapping[str, object],
    hook_event_name: str,
) -> dict[str, object]:
    """Translate Guard hook JSON into Cursor hook stdout JSON."""

    permission = _cursor_permission_for_policy(policy_action, guard_payload)
    reason = _cursor_block_reason(guard_payload)
    raw_event = hook_event_name.strip().lower()
    if raw_event == "beforereadfile":
        read_permission = _cursor_read_file_permission(permission)
        response: dict[str, object] = {"permission": read_permission}
        if read_permission == "deny":
            response["user_message"] = reason
        return {key: value for key, value in response.items() if value is not None}
    response: dict[str, object] = {"permission": permission}
    if permission != "allow":
        response["user_message"] = reason
        response["agent_message"] = reason
    return {key: value for key, value in response.items() if value is not None}


def cursor_hook_should_block(*, policy_action: str) -> bool:
    return policy_action in {"block", "sandbox-required"}


def _raw_hook_event_name(payload: Mapping[str, object]) -> str:
    for key in ("hook_event_name", "hookEventName", "hook_name", "hookName", "event", "eventName"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip().lower()
    return ""


def _tool_input_dict(value: object) -> dict[str, object]:
    if isinstance(value, dict):
        return dict(value)
    if isinstance(value, list):
        return {"arguments": list(value)}
    if isinstance(value, str) and value.strip():
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError:
            return {"raw": value.strip()}
        if isinstance(parsed, dict):
            return dict(parsed)
        if isinstance(parsed, list):
            return {"arguments": list(parsed)}
    return {}


def _cursor_permission_for_policy(
    policy_action: str,
    guard_payload: Mapping[str, object] | None = None,
) -> str:
    del guard_payload
    if not is_guard_action(policy_action):
        return "deny"
    if policy_action in {"block", "sandbox-required"}:
        return "deny"
    if policy_action in {"require-reapproval", "review"}:
        return "ask"
    return "allow"


def _cursor_read_file_permission(permission: str) -> str:
    if permission in {"deny", "ask"}:
        return "deny"
    return "allow"


def _cursor_block_reason(guard_payload: Mapping[str, object]) -> str:
    for key in ("review_hint", "risk_summary", "why_now", "risk_headline"):
        value = guard_payload.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    decision = guard_payload.get("decision_v2_json")
    if isinstance(decision, Mapping):
        for key in ("harness_message", "retry_instruction", "user_body", "user_title"):
            value = decision.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
    return "HOL Guard blocked this Cursor action."
