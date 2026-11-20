"""Resident bridge for policy-source fence-window accounting."""

from __future__ import annotations

import time
from pathlib import Path

from .native_execution import _resident_request

_FEATURE = "hook-policy-fence-window-write-v1"
_REQUEST_SCHEMA = "guard-hook-policy-fence-window-request.v1"
_RESULT_SCHEMA = "guard-hook-policy-fence-window-result.v1"
_TIMEOUT_SECONDS = 0.1


def record_policy_fence_window(
    guard_home: Path,
    *,
    action: str,
    admitted: bool | None = None,
    attempt_until_micros: int | None = None,
    request_id: str,
    deadline: float | None = None,
) -> None:
    """Update window state and let the resident persist completed events."""
    try:
        canonical_home = guard_home.resolve(strict=False)
    except (OSError, RuntimeError):
        canonical_home = guard_home
    request: dict[str, object] = {
        "schema": _REQUEST_SCHEMA,
        "request_id": request_id,
        "guard_home": str(canonical_home),
        "action": action,
        "persist_events": True,
    }
    if admitted is not None:
        request["admitted"] = admitted
    if attempt_until_micros is not None:
        request["attempt_until_micros"] = attempt_until_micros
    try:
        # Leave is cleanup for a successful enter. Keep its short transport
        # budget even when the hook's decision deadline has elapsed so the
        # resident registration cannot be stranded.
        timeout_seconds = _TIMEOUT_SECONDS
        if action != "leave" and deadline is not None:
            timeout_seconds = min(timeout_seconds, deadline - time.monotonic())
        if timeout_seconds <= 0:
            return
        _resident_request(
            operation="hook_policy_fence_window",
            request=request,
            guard_home=canonical_home,
            timeout_seconds=timeout_seconds,
            required_feature=_FEATURE,
            response_schema=_RESULT_SCHEMA,
            record_resilience=False,
        )
    except (OSError, RuntimeError, TypeError, ValueError):
        return


__all__ = ["record_policy_fence_window"]
