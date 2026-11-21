"""Resident-owned projections of incoming hook payloads.

The Python control plane uses this bridge only to obtain facts the Rust
resident already normalizes. It does not classify or reinterpret the reply.
"""

from __future__ import annotations

import math
import os
import time
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from .mdm.runtime_request import runtime_answer
from .native_execution import _resident_request
from .native_runtime import native_runtime_status
from .native_runtime_resilience import native_record_resident_failure, native_record_resident_success

_FEATURE = "hook-payload-facts-v1"
_REQUEST_SCHEMA = "guard-hook-payload-facts-request.v1"
_RESULT_SCHEMA = "guard-hook-payload-facts-result.v1"
_PAYLOAD_FACTS_MAX_REQUEST_BYTES = 6 * 1024 * 1024
_HOOK_EVENT_KEYS = ("event", "eventName", "hook_event_name", "hookEventName", "hook_name", "hookName")
_HOOK_BUDGET_SCALES = (("guard_remaining_seconds", 1.0), ("guard_remaining_ms", 1000.0))
_CONNECTOR_FEATURE = "hook-connector-facts-v1"
_CONNECTOR_REQUEST_SCHEMA = "guard-hook-connector-facts-request.v1"
_CONNECTOR_RESULT_SCHEMA = "guard-hook-connector-facts-result.v1"
_CONNECTOR_MAX_REQUEST_BYTES = 2 * 1024 * 1024
_CONNECTOR_LOOKUP_REASON_CODES = frozenset(
    {
        "native_command_review_required",
        "native_workspace_containment_executable_outside_roots",
    }
)
_CONNECTOR_LOOKUP_MAX_SECONDS = 0.25
_CONNECTOR_QUEUE_RESERVE_SECONDS = 0.35


@dataclass(frozen=True, slots=True)
class NativePayloadFacts:
    event_name: str
    command_only: bool
    command: str | None
    tool_name: str
    launch_target: str


def native_hook_facts(
    payload: Mapping[str, object], guard_home: Path, *, deadline: float | None = None
) -> NativePayloadFacts | None:
    """Return resident-normalized payload facts, or ``None`` on native absence."""

    event_payload: dict[str, object] = {
        key: payload[key]
        for key in (
            *_HOOK_EVENT_KEYS,
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
    wire: dict[str, object] = {
        "schema": _REQUEST_SCHEMA,
        "request_id": f"hook-payload-facts-{uuid.uuid4().hex}",
        "payload": event_payload,
    }
    try:
        status = native_runtime_status(deadline_monotonic=deadline)
        timeout_seconds = 1.0 if deadline is None else min(1.0, deadline - time.monotonic())
        if timeout_seconds <= 0:
            return None
        response = _resident_request(
            operation="hook_payload_facts",
            request=wire,
            guard_home=guard_home,
            timeout_seconds=timeout_seconds,
            required_feature=_FEATURE,
            response_schema=_RESULT_SCHEMA,
            max_request_bytes=_PAYLOAD_FACTS_MAX_REQUEST_BYTES,
            record_success=False,
            status=status,
        )
    except (OSError, RuntimeError, TypeError, ValueError):
        return None
    if response is None:
        return None
    result = response.get("result") if isinstance(response, Mapping) else None
    if not isinstance(result, Mapping):
        if status.identity is not None:
            native_record_resident_failure(
                status.identity.sha256, guard_home, reason="native_hook_payload_facts_result"
            )
        return None
    event = result.get("event_name")
    command_only = result.get("command_only")
    command = result.get("command")
    tool_name = result.get("tool_name")
    launch_target = result.get("launch_target")
    if (
        not isinstance(event, str)
        or not event
        or not isinstance(command_only, bool)
        or (command is not None and not isinstance(command, str))
        or not isinstance(tool_name, str)
        or not tool_name
        or not isinstance(launch_target, str)
        or not launch_target
    ):
        if status.identity is not None:
            native_record_resident_failure(
                status.identity.sha256, guard_home, reason="native_hook_payload_facts_result"
            )
        return None
    if status.identity is not None:
        native_record_resident_success(status.identity.sha256, guard_home)
    return NativePayloadFacts(event, command_only, command, tool_name, launch_target)


def native_hook_event(payload: Mapping[str, object], guard_home: Path, *, deadline: float | None = None) -> str | None:
    # Event identity does not depend on tool input. Keep this request small so
    # a large action payload cannot turn event lookup into an outage.
    event_payload = {key: payload[key] for key in _HOOK_EVENT_KEYS if key in payload}
    facts = native_hook_facts(event_payload, guard_home, deadline=deadline)
    return facts.event_name if facts is not None else None


def native_cli_hook_admission(payload: Mapping[str, object], *, started_at: float) -> tuple[str | None, float]:
    """Read CLI admission facts before a resident is necessarily available."""
    wire: dict[str, object] = {key: value for key in _HOOK_EVENT_KEYS if isinstance(value := payload.get(key), str)}
    transport_seconds = None
    for key, scale in _HOOK_BUDGET_SCALES:
        value = payload.get(key)
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or (isinstance(value, float) and not math.isfinite(value))
        ):
            continue
        wire[key] = value
        # Bound the lookup by the caller's raw time. Rust sets the review budget.
        if transport_seconds is None and value >= 0:
            transport_seconds = min(scale, value) / scale
    if transport_seconds is None:
        transport_seconds = 1.0
    facts = runtime_answer(
        "native-hook-cli-admission-v1",
        "hook-cli-admission",
        wire,
        output_limit=64 * 1024,
        deadline=started_at + transport_seconds,
    )
    if facts is None:
        return None, started_at
    event, budget = facts.get("event_name"), facts.get("budget_seconds")
    if (
        isinstance(event, str)
        and isinstance(budget, (int, float))
        and not isinstance(budget, bool)
        and 0 < budget <= 10
    ):
        return event, started_at + budget
    return None, started_at


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

    if not isinstance(reason_code, str) or reason_code not in _CONNECTOR_LOOKUP_REASON_CODES:
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
    wire: dict[str, object] = {
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
        lookup_deadline = None if deadline is None else deadline - _CONNECTOR_QUEUE_RESERVE_SECONDS
        status = native_runtime_status(deadline_monotonic=lookup_deadline)
        timeout_seconds = _CONNECTOR_LOOKUP_MAX_SECONDS
        if lookup_deadline is not None:
            timeout_seconds = min(timeout_seconds, lookup_deadline - time.monotonic())
        if timeout_seconds <= 0:
            return None
        response = _resident_request(
            operation="hook_connector_facts",
            request=wire,
            guard_home=guard_home,
            timeout_seconds=timeout_seconds,
            required_feature=_CONNECTOR_FEATURE,
            response_schema=_CONNECTOR_RESULT_SCHEMA,
            max_request_bytes=_CONNECTOR_MAX_REQUEST_BYTES,
            record_success=False,
            status=status,
        )
    except (OSError, RuntimeError, TypeError, ValueError):
        return None
    if response is None:
        return None
    result = response.get("result") if isinstance(response, Mapping) else None
    lookup = result.get("connector_lookup") if isinstance(result, Mapping) else None
    if lookup is None and isinstance(result, Mapping) and "connector_lookup" in result:
        if status.identity is not None:
            native_record_resident_success(status.identity.sha256, guard_home)
        return None
    if not isinstance(lookup, Mapping):
        if status.identity is not None:
            native_record_resident_failure(
                status.identity.sha256, guard_home, reason="native_hook_connector_facts_result"
            )
        return None
    command = lookup.get("command")
    cwd = lookup.get("cwd")
    env = lookup.get("env")
    if (
        set(lookup) != {"command", "cwd", "home_dir", "user_home", "env"}
        or not isinstance(command, str)
        or not command.strip()
        or not isinstance(cwd, str)
        or not cwd.strip()
        or (lookup.get("home_dir") is not None and not isinstance(lookup.get("home_dir"), str))
        or not isinstance(lookup.get("user_home"), str)
        or not isinstance(env, Mapping)
        or not all(isinstance(key, str) and isinstance(value, str) for key, value in env.items())
    ):
        if status.identity is not None:
            native_record_resident_failure(
                status.identity.sha256, guard_home, reason="native_hook_connector_facts_result"
            )
        return None
    if status.identity is not None:
        native_record_resident_success(status.identity.sha256, guard_home)
    return dict(lookup)


__all__ = [
    "NativePayloadFacts",
    "native_cli_hook_admission",
    "native_connector_lookup",
    "native_hook_event",
    "native_hook_facts",
]
