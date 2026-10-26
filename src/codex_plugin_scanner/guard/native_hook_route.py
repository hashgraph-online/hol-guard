"""The hook pipeline's dispatch route, answered by the native runtime.

The CLI hook pipeline used to walk a ladder of Python conditions to pick the
handler that answers a prepared hook payload. The resident now returns that
order as a plan of handler names; the pipeline runs each handler in a fixed
table until one answers and decides nothing itself. A reply that is not a
bound, strictly decoded ``ok`` with a well-formed plan raises
``NativeHookDecisionError`` and the caller answers with the host outage
response, so a route is never guessed.
"""

from __future__ import annotations

import dataclasses
import functools
from collections.abc import Mapping
from pathlib import Path
from typing import Any, NamedTuple

from .native_execution import _resident_request
from .native_hook_decision import (
    _INVALID,
    _MAX_REQUEST_BYTES,
    _OPERATION,
    _TIMEOUT_SECONDS,
    _UNAVAILABLE,
    NativeHookDecisionError,
    _shape,
)
from .native_resident_decision import resident_decide

HOOK_DECISION_HOOK_ROUTE_FEATURE = "hook-decision-hook-route-v1"

PASSTHROUGH_HANDLER = "passthrough"
# Handlers that answer every hook they run for; a plan ends at the first.
TERMINAL_HANDLERS = frozenset(
    {
        PASSTHROUGH_HANDLER,
        "copilot_pretool",
        "claude_permission_request",
        "claude_permission_prompt",
        "claude_stop",
        "generic_flow",
    }
)
ROUTE_HANDLERS = TERMINAL_HANDLERS | frozenset(
    {
        "claude_guard_question",
        "native_edge",
        "edge_unavailable",
        "containment",
        "copilot_permission_request",
        "runtime_artifact",
        "artifact_flow",
    }
)
_INPUT_FIELDS: Mapping[str, Any] = {
    "harness": str,
    "canonical_harness": str,
    "invoked_event": str,
    "hook_event": str,
    "runtime_event": str,
    "notification_type": str,
    "copilot_stage": str,
    "copilot_tool_call_present": bool,
    "copilot_permission_request": bool,
}
_ROUTE_FIELDS: Mapping[str, Any] = {"plan": list, "event_name": str}


class NativeHookRoute(NamedTuple):
    """The handlers that may answer a hook, in order, and the event they answer."""

    plan: tuple[str, ...]
    event_name: str


def native_hook_route(
    inputs: Mapping[str, object],
    *,
    guard_home: Path | None = None,
    budget_seconds: float | None = None,
) -> NativeHookRoute:
    """The ordered handlers that may answer this hook, and nothing else.

    ``budget_seconds`` is what the harness still allows this hook. The query
    never waits longer than that, and an exhausted budget is an outage without
    asking, so a slow resident cannot hold the hook past the harness deadline.
    """

    _shape(dict(inputs), _INPUT_FIELDS)
    timeout = _TIMEOUT_SECONDS if budget_seconds is None else min(_TIMEOUT_SECONDS, budget_seconds)
    if timeout <= 0:
        raise NativeHookDecisionError(_UNAVAILABLE)

    def validate(payload: dict[str, Any]) -> None:
        if set(payload) != {"kind", *_ROUTE_FIELDS}:
            raise NativeHookDecisionError(_INVALID)
        route = _shape({key: payload[key] for key in _ROUTE_FIELDS}, _ROUTE_FIELDS)
        plan = route["plan"]
        if (
            not plan
            or not all(isinstance(step, str) and step in ROUTE_HANDLERS for step in plan)
            or len(set(plan)) != len(plan)
            or plan[-1] not in TERMINAL_HANDLERS
            or any(step in TERMINAL_HANDLERS for step in plan[:-1])
            or (PASSTHROUGH_HANDLER in plan and len(plan) != 1)
            or not route["event_name"]
        ):
            raise NativeHookDecisionError(_INVALID)

    payload = resident_decide(
        dataclasses.replace(_OPERATION, feature=HOOK_DECISION_HOOK_ROUTE_FEATURE, timeout_seconds=timeout),
        functools.partial(_resident_request, max_request_bytes=_MAX_REQUEST_BYTES),
        {"kind": "hook_route", "inputs": dict(inputs)},
        guard_home,
        validate,
    )
    return NativeHookRoute(tuple(payload["plan"]), payload["event_name"])


__all__ = [
    "HOOK_DECISION_HOOK_ROUTE_FEATURE",
    "PASSTHROUGH_HANDLER",
    "ROUTE_HANDLERS",
    "TERMINAL_HANDLERS",
    "NativeHookRoute",
    "native_hook_route",
]
