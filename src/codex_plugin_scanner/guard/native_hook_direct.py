"""Transport for the Rust direct-hook authority."""

from __future__ import annotations

import time
from collections.abc import Mapping
from pathlib import Path

from .native_execution import _resident_request
from .native_hook_edge import _decode_edge
from .native_runtime import native_runtime_status

HOOK_DIRECT_FEATURE = "hook-direct-v1"


def native_hook_direct(
    *,
    harness: str,
    guard_home: Path,
    payload: Mapping[str, object],
    workspace: Path | None,
    home_dir: Path | None,
    deadline: float | None,
    emergency_safe_only: bool = False,
) -> dict[str, object] | None:
    """Ask Rust to answer or defer one direct hook request."""

    status = native_runtime_status(deadline_monotonic=deadline)
    if status.identity is None:
        return None
    timeout_seconds = 0.75 if deadline is None else min(0.75, deadline - time.monotonic())
    if timeout_seconds <= 0:
        return None
    request: dict[str, object] = {
        "harness": harness,
        "guard_home": str(guard_home),
        "home_dir": str(home_dir) if home_dir is not None else None,
        "workspace": str(workspace) if workspace is not None else None,
        "deadline_budget_ms": max(1, int(timeout_seconds * 1000)),
        "emergency_safe_only": emergency_safe_only,
        "payload": dict(payload),
    }
    try:
        response = _resident_request(
            operation="hook_direct",
            request=request,
            guard_home=guard_home,
            timeout_seconds=timeout_seconds,
            required_feature=HOOK_DIRECT_FEATURE,
            record_success=False,
            status=status,
        )
    except (OSError, RuntimeError, TypeError, ValueError):
        return None
    if not isinstance(response, Mapping):
        return None
    if response.get("outcome") == "answer":
        edge = response.get("edge")
        if not isinstance(edge, Mapping):
            return None
        return _decode_edge(dict(edge))
    if response.get("outcome") == "defer":
        return {"outcome": "defer", "reason": response.get("reason")}
    return None


__all__ = ["HOOK_DIRECT_FEATURE", "native_hook_direct"]
