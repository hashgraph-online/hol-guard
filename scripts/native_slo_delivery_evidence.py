"""Finite evidence from one already completed registered hook process.

This is an observation of delivered JSON, never a native-route witness or a
replacement for the caller's full-shape validator. No child is invoked here.
"""

from __future__ import annotations

import json
from collections.abc import Mapping

from codex_plugin_scanner.guard.codex_hook_launch_runtime import BoundedHookProcessResult
from scripts.native_slo_observation_failure import verdict_evidence

_PERMISSIONS = frozenset({"allow", "deny", "ask"})


def delivery_evidence(
    result: BoundedHookProcessResult, *, validated: bool
) -> tuple[dict[str, object], dict[str, object]]:
    """Project existing bounded streams without copying reasons or body fields."""
    process: dict[str, object] = {
        "available": True,
        "exit_code": result.returncode,
        "timed_out": result.timed_out,
        "containment_failed": result.containment_failed,
        "limit_exceeded": result.output_limit_exceeded,
        "stderr_present": bool(result.stderr),
        "shape_validation": "passed" if validated else "not_run",
    }
    try:
        response: object = json.loads(result.stdout)
    except (ValueError, RecursionError):
        process["json_shape"] = "invalid_json" if result.stdout.strip() else "empty"
        return process, {"available": False}
    if not isinstance(response, Mapping):
        process["json_shape"] = "nonobject"
        return process, {"available": False}
    process["json_shape"] = "object"
    observed = verdict_evidence(response)["delivered"]
    if not isinstance(observed, dict):
        raise TypeError("registered_delivery_projection_invalid")
    for field in ("continue", "cancel"):
        if field in response:
            value = response[field]
            observed[field] = value if type(value) is bool else "invalid_type"
    hook = response.get("hookSpecificOutput")
    for field, value in (
        ("permission", response.get("permission")),
        ("permission_decision", response.get("permissionDecision")),
        ("hook_permission", hook.get("permissionDecision") if isinstance(hook, Mapping) else None),
    ):
        if value is not None:
            observed[field] = value if isinstance(value, str) and value in _PERMISSIONS else "unrecognized"
    return process, observed


__all__ = ["delivery_evidence"]
