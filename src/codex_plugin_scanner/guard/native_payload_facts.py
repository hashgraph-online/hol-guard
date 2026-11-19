"""Resident-owned projections of incoming hook payloads.

The Python control plane uses this bridge only to obtain facts the Rust
resident already normalizes. It does not classify or reinterpret the reply.
"""

from __future__ import annotations

import os
import time
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from .native_execution import _resident_request

_FEATURE = "hook-payload-facts-v1"
_REQUEST_SCHEMA = "guard-hook-payload-facts-request.v1"
_RESULT_SCHEMA = "guard-hook-payload-facts-result.v1"
_CONNECTOR_FEATURE = "hook-connector-facts-v1"
_CONNECTOR_REQUEST_SCHEMA = "guard-hook-connector-facts-request.v1"
_CONNECTOR_RESULT_SCHEMA = "guard-hook-connector-facts-result.v1"
_CONNECTOR_MAX_REQUEST_BYTES = 2 * 1024 * 1024


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


def native_connector_lookup(
    payload: Mapping[str, object],
    guard_home: Path,
    *,
    reason_code: object,
    workspace: Path | None,
    home_dir: Path | None,
    deadline: float | None = None,
) -> dict[str, object] | None:
    """Return the Rust-owned launch lookup for a connector setup review."""

    if not isinstance(reason_code, str) or not reason_code:
        return None
    event_payload = {
        key: payload[key]
        for key in (
            "tool_input",
            "toolInput",
            "arguments",
            "command",
            "cmd",
            "shell_command",
            "shellCommand",
            "cwd",
            "guard_execution_environment",
        )
        if key in payload
    }
    timeout_seconds = 1.0 if deadline is None else min(1.0, deadline - time.monotonic())
    if timeout_seconds <= 0:
        return None
    wire = {
        "schema": _CONNECTOR_REQUEST_SCHEMA,
        "request_id": f"hook-connector-facts-{uuid.uuid4().hex}",
        "payload": event_payload,
        "reason_code": reason_code,
        "workspace": None if workspace is None else str(workspace),
        "home_dir": None if home_dir is None else str(home_dir),
        "user_home": str(Path.home()),
        "env": dict(os.environ),
    }
    try:
        response = _resident_request(
            operation="hook_connector_facts",
            request=wire,
            guard_home=guard_home,
            timeout_seconds=timeout_seconds,
            required_feature=_CONNECTOR_FEATURE,
            response_schema=_CONNECTOR_RESULT_SCHEMA,
            max_request_bytes=_CONNECTOR_MAX_REQUEST_BYTES,
        )
    except (OSError, RuntimeError, TypeError, ValueError):
        return None
    result = response.get("result") if isinstance(response, Mapping) else None
    lookup = result.get("connector_lookup") if isinstance(result, Mapping) else None
    if not isinstance(lookup, Mapping):
        return None
    if (
        set(lookup) != {"command", "cwd", "home_dir", "user_home", "env"}
        or
        not isinstance(lookup.get("command"), str)
        or not lookup.get("command", "").strip()
        or not isinstance(lookup.get("cwd"), str)
        or not lookup.get("cwd", "").strip()
        or (lookup.get("home_dir") is not None and not isinstance(lookup.get("home_dir"), str))
        or not isinstance(lookup.get("user_home"), str)
        or not isinstance(lookup.get("env"), Mapping)
        or not all(isinstance(key, str) and isinstance(value, str) for key, value in lookup["env"].items())
    ):
        return None
    return dict(lookup)


__all__ = ["NativePayloadFacts", "native_connector_lookup", "native_hook_event", "native_hook_facts"]
