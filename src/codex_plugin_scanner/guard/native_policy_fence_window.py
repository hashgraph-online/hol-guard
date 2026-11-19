"""Resident bridge for policy-source fence-window accounting."""

from __future__ import annotations

import time
import uuid
from collections.abc import Mapping, Sequence
from pathlib import Path

from .native_execution import _resident_request

_FEATURE = "hook-policy-fence-window-v1"
_REQUEST_SCHEMA = "guard-hook-policy-fence-window-request.v1"
_RESULT_SCHEMA = "guard-hook-policy-fence-window-result.v1"
_TIMEOUT_SECONDS = 0.1


def record_policy_fence_window(
    guard_home: Path,
    *,
    action: str,
    admitted: bool | None = None,
    waited_ms: int | None = None,
    attempt_until_micros: int | None = None,
    request_id: str | None = None,
    deadline: float | None = None,
) -> Mapping[str, object] | Sequence[Mapping[str, object]] | None:
    """Update resident fence-window state and return completed events, if any."""

    if action not in {"enter", "leave", "attempt", "absorb_direct"}:
        return None
    try:
        canonical_home = guard_home.resolve(strict=False)
    except (OSError, RuntimeError):
        canonical_home = guard_home
    request: dict[str, object] = {
        "schema": _REQUEST_SCHEMA,
        "request_id": request_id or f"policy-fence-window-{uuid.uuid4().hex}",
        "guard_home": str(canonical_home),
        "action": action,
    }
    if admitted is not None:
        request["admitted"] = admitted
    if waited_ms is not None:
        request["waited_ms"] = waited_ms
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
            return None
        response = _resident_request(
            operation="hook_policy_fence_window",
            request=request,
            guard_home=canonical_home,
            timeout_seconds=timeout_seconds,
            required_feature=_FEATURE,
            response_schema=_RESULT_SCHEMA,
            record_resilience=False,
        )
    except (OSError, RuntimeError, TypeError, ValueError):
        return None
    result = response.get("result") if isinstance(response, Mapping) else None
    if not isinstance(result, Mapping) or result.get("request_id") != request["request_id"]:
        return None
    if set(result) == {"request_id", "window_event"}:
        events = [] if result.get("window_event") is None else [result["window_event"]]
    elif set(result) == {"request_id", "window_event", "window_events"}:
        raw_events = result.get("window_events")
        if not isinstance(raw_events, list):
            return None
        events = raw_events
        if events and events[0] != result.get("window_event"):
            return None
    else:
        return None
    if not events:
        return {}
    checked: list[Mapping[str, object]] = []
    for event in events:
        if not isinstance(event, Mapping) or set(event) != {"event_name", "payload", "occurred_at"}:
            return None
        payload = event.get("payload")
        if (
            event.get("event_name") != "policy_source_fence_window"
            or not isinstance(event.get("occurred_at"), str)
            or not isinstance(payload, Mapping)
            or set(payload) != {"started_at", "ended_at", "absorbed_calls", "exhausted_calls"}
            or not isinstance(payload.get("started_at"), str)
            or not isinstance(payload.get("ended_at"), str)
            or not isinstance(payload.get("absorbed_calls"), int)
            or isinstance(payload.get("absorbed_calls"), bool)
            or not isinstance(payload.get("exhausted_calls"), int)
            or isinstance(payload.get("exhausted_calls"), bool)
        ):
            return None
        checked.append(dict(event))
    return checked[0] if len(checked) == 1 else checked


__all__ = ["record_policy_fence_window"]
