"""Resident-owned recovery posture for the hook policy admission barrier."""

from __future__ import annotations

import time
import uuid
from pathlib import Path

from .native_execution import _resident_request
from .native_runtime import native_runtime_status

_FEATURE = "hook-policy-admission-v1"
_REQUEST_SCHEMA = "guard-hook-policy-admission-request.v1"
_RESULT_SCHEMA = "guard-hook-policy-admission-result.v1"


def native_policy_not_ready_reason(
    last_error: object,
    resident_failure_streak: object,
    guard_home: Path,
    *,
    deadline: float | None = None,
) -> str | None:
    """Return the Rust-owned fail-safe reason, or ``None`` on native absence."""

    error = last_error if isinstance(last_error, str) else None
    streak = resident_failure_streak if isinstance(resident_failure_streak, int) else 0
    if isinstance(streak, bool) or streak < 0:
        streak = 0
    status = native_runtime_status(deadline_monotonic=deadline)
    timeout_seconds = 0.5 if deadline is None else min(0.5, deadline - time.monotonic())
    if timeout_seconds <= 0:
        return None
    request: dict[str, object] = {
        "schema": _REQUEST_SCHEMA,
        "request_id": f"hook-policy-admission-{uuid.uuid4().hex}",
        "last_error": error.strip() if error and error.strip() else None,
        "resident_failure_streak": streak,
    }
    try:
        response = _resident_request(
            operation="hook_policy_admission",
            request=request,
            guard_home=guard_home,
            timeout_seconds=timeout_seconds,
            required_feature=_FEATURE,
            response_schema=_RESULT_SCHEMA,
            status=status,
        )
    except (OSError, RuntimeError, TypeError, ValueError):
        return None
    result = response.get("result") if isinstance(response, dict) else None
    if (
        not isinstance(result, dict)
        or set(result) != {"request_id", "reason"}
        or result.get("request_id") != request["request_id"]
    ):
        return None
    reason = result.get("reason")
    return reason if isinstance(reason, str) and reason else None


__all__ = ["native_policy_not_ready_reason"]
