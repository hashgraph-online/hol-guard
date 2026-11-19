"""Resident bridge for policy-source fence-window accounting."""

from __future__ import annotations

import uuid
from collections.abc import Mapping
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
) -> Mapping[str, object] | None:
    """Update resident fence-window state and return a completed event, if any."""

    if action not in {"enter", "leave", "absorb_direct"}:
        return None
    request: dict[str, object] = {
        "schema": _REQUEST_SCHEMA,
        "request_id": f"policy-fence-window-{uuid.uuid4().hex}",
        "guard_home": str(guard_home),
        "action": action,
    }
    if admitted is not None:
        request["admitted"] = admitted
    if waited_ms is not None:
        request["waited_ms"] = waited_ms
    try:
        response = _resident_request(
            operation="hook_policy_fence_window",
            request=request,
            guard_home=guard_home,
            timeout_seconds=_TIMEOUT_SECONDS,
            required_feature=_FEATURE,
            response_schema=_RESULT_SCHEMA,
        )
    except (OSError, RuntimeError, TypeError, ValueError):
        return None
    result = response.get("result") if isinstance(response, Mapping) else None
    event = result.get("window_event") if isinstance(result, Mapping) else None
    if event is None:
        return None
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
    return dict(event)


__all__ = ["record_policy_fence_window"]
