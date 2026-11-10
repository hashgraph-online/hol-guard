"""Normalize daemon hook payloads into the native review request model."""

from __future__ import annotations

from collections.abc import Mapping


def runtime_hook_event_name(payload: Mapping[str, object]) -> str:
    for key in ("event", "eventName", "hook_event_name", "hookEventName", "hook_name", "hookName"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            raw = value.strip()
            compact = raw.lower().replace("_", "").replace("-", "")
            if compact in {
                "pretool",
                "pretooluse",
                "pretoolcall",
                "beforeshellexecution",
                "beforereadfile",
                "beforewritefile",
                "beforemcpexecution",
            }:
                return "PreToolUse"
            if compact in {
                "posttool",
                "posttooluse",
                "posttoolcall",
                "aftershellexecution",
                "afterreadfile",
                "afterwritefile",
                "aftermcpexecution",
            }:
                return "PostToolUse"
            if compact in {"permissionrequest", "permissionrequestv2"}:
                return "PermissionRequest"
            if compact in {"prompt", "userpromptsubmit", "userpromptsubmitted"}:
                return "UserPromptSubmit"
            return raw
    return "PreToolUse"


def pre_tool_input(payload: Mapping[str, object]) -> Mapping[str, object] | None:
    """Return the tool input for snake_case and camelCase (ZCode, Devin, Grok) payloads."""

    for key in ("tool_input", "toolInput"):
        candidate = payload.get(key)
        if isinstance(candidate, Mapping):
            return candidate
    return None


def pre_tool_command(payload: Mapping[str, object]) -> str | None:
    for candidate in (pre_tool_input(payload), payload.get("arguments"), payload):
        if not isinstance(candidate, Mapping):
            continue
        for key in ("command", "cmd", "shell_command", "shellCommand"):
            value = candidate.get(key)
            if isinstance(value, str) and value.strip():
                return value
    return None


def native_review_tool_name(payload: Mapping[str, object]) -> str:
    for key in ("tool_name", "toolName", "tool"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return "tool"


def native_review_launch_target(payload: Mapping[str, object]) -> str:
    command = pre_tool_command(payload)
    if command is not None:
        return command
    tool_input = pre_tool_input(payload)
    if tool_input is not None:
        for key in ("url", "path", "file_path", "target"):
            value = tool_input.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
    return f"tool:{native_review_tool_name(payload)}"


__all__ = [
    "native_review_launch_target",
    "native_review_tool_name",
    "pre_tool_command",
    "pre_tool_input",
    "runtime_hook_event_name",
]
