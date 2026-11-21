"""Transport for the Rust direct-hook authority."""

from __future__ import annotations

import time
from collections.abc import Mapping
from pathlib import Path
from typing import cast

from .native_execution import _resident_request
from .native_hook_edge import _decode_edge
from .native_runtime import native_runtime_status
from .native_runtime_resilience import native_record_resident_failure, native_record_resident_success

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
    lifecycle_only: bool = False,
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
    if lifecycle_only:
        request["lifecycle_only"] = True
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
    outcome = response.get("outcome")
    if outcome == "defer":
        native_record_resident_success(status.identity.sha256, guard_home)
        return {"outcome": "defer", "reason": response.get("reason")}
    if outcome == "answer":
        edge = response.get("edge")
        decoded = cast(dict[str, object] | None, _decode_edge(dict(edge))) if isinstance(edge, Mapping) else None
        # Lifecycle answers are intentionally smaller than a review edge. The
        # resident has no tool-review receipt to return, only the rendered
        # harness response.
        if decoded is None and isinstance(edge, Mapping) and set(edge) == {"harness_response"}:
            rendered = edge.get("harness_response")
            if isinstance(rendered, Mapping):
                decoded = cast(
                    dict[str, object],
                    {"harness_response": {str(key): value for key, value in rendered.items()}},
                )
        if decoded is not None:
            native_record_resident_success(status.identity.sha256, guard_home)
            return decoded
    native_record_resident_failure(status.identity.sha256, guard_home, reason="native_hook_direct_schema")
    return None


__all__ = ["HOOK_DIRECT_FEATURE", "native_hook_direct"]
