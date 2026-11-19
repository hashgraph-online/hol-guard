"""Fixture-only payload projections for retired Python route oracles."""

from __future__ import annotations

from collections.abc import Mapping


def fixture_event_name(payload: Mapping[str, object]) -> str:
    for key in ("event", "eventName", "hook_event_name", "hookEventName", "hook_name", "hookName"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            raw = value.strip()
            compact = raw.lower().replace("_", "").replace("-", "")
            if compact in {
                "pretool", "pretooluse", "pretoolcall", "beforeshellexecution",
                "beforereadfile", "beforewritefile", "beforemcpexecution",
            }:
                return "PreToolUse"
            if compact in {
                "posttool", "posttooluse", "posttoolcall", "aftershellexecution",
                "afterreadfile", "afterwritefile", "aftermcpexecution",
            }:
                return "PostToolUse"
            if compact in {"permissionrequest", "permissionrequestv2"}:
                return "PermissionRequest"
            if compact in {"prompt", "userpromptsubmit", "userpromptsubmitted"}:
                return "UserPromptSubmit"
            return raw
    return "PreToolUse"


def fixture_command(payload: Mapping[str, object]) -> str | None:
    for candidate in (payload.get("tool_input"), payload.get("toolInput"), payload.get("arguments"), payload):
        if not isinstance(candidate, Mapping):
            continue
        for key in ("command", "cmd", "shell_command", "shellCommand"):
            value = candidate.get(key)
            if isinstance(value, str) and value.strip():
                return value
    return None
