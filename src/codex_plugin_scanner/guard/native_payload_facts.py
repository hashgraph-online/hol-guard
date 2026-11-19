"""Resident-owned projections of incoming hook payloads.

The Python control plane uses this bridge only to obtain facts the Rust
resident already normalizes. It does not classify or reinterpret the reply.
"""

from __future__ import annotations

import time
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from .native_execution import _resident_request

_FEATURE = "hook-payload-facts-v1"
_REQUEST_SCHEMA = "guard-hook-payload-facts-request.v1"
_RESULT_SCHEMA = "guard-hook-payload-facts-result.v1"


@dataclass(frozen=True, slots=True)
class NativePayloadFacts:
    event_name: str
    tool_input: Mapping[str, object] | None
    command: str | None
    tool_name: str
    launch_target: str


def native_hook_facts(
    payload: Mapping[str, object], guard_home: Path, *, deadline: float | None = None
) -> NativePayloadFacts | None:
    """Return resident-normalized payload facts, or ``None`` on native absence."""

    event_payload = {
        key: payload[key]
        for key in (
            "event",
            "eventName",
            "hook_event_name",
            "hookEventName",
            "hook_name",
            "hookName",
            "tool_input",
            "toolInput",
            "arguments",
            "tool_name",
            "toolName",
            "tool",
            "command",
            "cmd",
            "shell_command",
            "shellCommand",
        )
        if key in payload
    }
    wire = {
        "schema": _REQUEST_SCHEMA,
        "request_id": f"hook-payload-facts-{uuid.uuid4().hex}",
        "payload": event_payload,
    }
    timeout_seconds = 1.0 if deadline is None else min(1.0, deadline - time.monotonic())
    if timeout_seconds <= 0:
        return None
    try:
        response = _resident_request(
            operation="hook_payload_facts",
            request=wire,
            guard_home=guard_home,
            timeout_seconds=timeout_seconds,
            required_feature=_FEATURE,
            response_schema=_RESULT_SCHEMA,
        )
    except (OSError, RuntimeError, TypeError, ValueError):
        return None
    result = response.get("result") if isinstance(response, Mapping) else None
    if not isinstance(result, Mapping):
        return None
    event = result.get("event_name")
    tool_input = result.get("tool_input")
    command = result.get("command")
    tool_name = result.get("tool_name")
    launch_target = result.get("launch_target")
    if (
        not isinstance(event, str)
        or not event
        or (tool_input is not None and not isinstance(tool_input, Mapping))
        or (command is not None and not isinstance(command, str))
        or not isinstance(tool_name, str)
        or not tool_name
        or not isinstance(launch_target, str)
        or not launch_target
    ):
        return None
    return NativePayloadFacts(event, tool_input, command, tool_name, launch_target)


def native_hook_event(
    payload: Mapping[str, object], guard_home: Path, *, deadline: float | None = None
) -> str | None:
    facts = native_hook_facts(payload, guard_home, deadline=deadline)
    return facts.event_name if facts is not None else None


__all__ = ["NativePayloadFacts", "native_hook_event", "native_hook_facts"]


def fallback_runtime_event_name(payload: Mapping[str, object]) -> str:
    """Compatibility projection used only when the resident is unavailable."""

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


def fallback_tool_input(payload: Mapping[str, object]) -> Mapping[str, object] | None:
    for key in ("tool_input", "toolInput"):
        candidate = payload.get(key)
        if isinstance(candidate, Mapping):
            return candidate
    return None


def fallback_command(payload: Mapping[str, object]) -> str | None:
    for candidate in (fallback_tool_input(payload), payload.get("arguments"), payload):
        if not isinstance(candidate, Mapping):
            continue
        for key in ("command", "cmd", "shell_command", "shellCommand"):
            value = candidate.get(key)
            if isinstance(value, str) and value.strip():
                return value
    return None


def fallback_tool_name(payload: Mapping[str, object]) -> str:
    for key in ("tool_name", "toolName", "tool"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return "tool"


def fallback_launch_target(payload: Mapping[str, object]) -> str:
    command = fallback_command(payload)
    if command is not None:
        return command
    tool_input = fallback_tool_input(payload)
    if tool_input is not None:
        for key in ("url", "path", "file_path", "target"):
            value = tool_input.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
    return f"tool:{fallback_tool_name(payload)}"


__all__ += [
    "fallback_command",
    "fallback_launch_target",
    "fallback_runtime_event_name",
    "fallback_tool_input",
    "fallback_tool_name",
]
