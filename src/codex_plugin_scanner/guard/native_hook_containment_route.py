"""The shape of the containment rewrite the edge answers.

The resident stamps every PreToolUse edge answer with its containment route
(``none``, ``sink`` or ``grant``), and the edge rewrites a sink-routed call
itself: the resident decides whether the sink takes the call, writes the
private request snapshot and returns the allow that runs the call in the
sink. The daemon only holds that allow to the routed shape, so an allow that
changes anything but the command line is the host outage response.
"""

from __future__ import annotations

from collections.abc import Mapping

_ROUTED_REASON = "native_contained_execution_routed"


def edge_routed_shape(routed: object, payload: Mapping[str, object]) -> bool:
    """Whether an edge's routed allow runs only a new command line for ``payload``'s call."""

    return _routed_shape(routed, _tool_input(payload))


def _routed_shape(routed: object, original: object) -> bool:
    """The allow runs only a new command line; every other field is the call's own."""

    if not isinstance(routed, dict) or not isinstance(original, dict):
        return False
    output = routed.get("hookSpecificOutput")
    if (
        set(routed) != {"policy_action", "reason_code", "hookSpecificOutput"}
        or routed["policy_action"] != "allow"
        or routed["reason_code"] != _ROUTED_REASON
        or not isinstance(output, dict)
        or set(output) != {"hookEventName", "permissionDecision", "updatedInput"}
        or output["hookEventName"] != "PreToolUse"
        or output["permissionDecision"] != "allow"
    ):
        return False
    updated = output["updatedInput"]
    if not isinstance(updated, dict) or not isinstance(updated.get("command"), str):
        return False
    return {**updated, "command": None} == {**original, "command": None}


def _tool_input(payload: Mapping[str, object]) -> object:
    return payload.get("tool_input", payload.get("toolInput"))


__all__ = ["edge_routed_shape"]
