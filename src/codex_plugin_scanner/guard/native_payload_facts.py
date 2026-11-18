"""Resident-owned projections of incoming hook payloads.

The Python control plane uses this bridge only to obtain facts the Rust
resident already normalizes. It does not classify or reinterpret the reply.
"""

from __future__ import annotations

import time
import uuid
from collections.abc import Mapping
from pathlib import Path

from .native_execution import _resident_request

_FEATURE = "hook-payload-facts-v1"
_REQUEST_SCHEMA = "guard-hook-payload-facts-request.v1"
_RESULT_SCHEMA = "guard-hook-payload-facts-result.v1"


def native_hook_event(
    payload: Mapping[str, object], guard_home: Path, *, deadline: float | None = None
) -> str | None:
    """Return the resident-normalized event, or ``None`` on native absence."""

    event_payload = {
        key: payload[key]
        for key in ("event", "eventName", "hook_event_name", "hookEventName", "hook_name", "hookName")
        if key in payload
    }
    wire = {
        "schema": _REQUEST_SCHEMA,
        "request_id": f"hook-payload-facts-{uuid.uuid4().hex}",
        "payload": event_payload,
    }
    timeout_seconds = 1.0 if deadline is None else min(1.0, deadline - time.monotonic())
    if timeout_seconds <= 0:
        return None
    try:
        response = _resident_request(
            operation="hook_payload_facts",
            request=wire,
            guard_home=guard_home,
            timeout_seconds=timeout_seconds,
            required_feature=_FEATURE,
            response_schema=_RESULT_SCHEMA,
        )
    except (OSError, RuntimeError, TypeError, ValueError):
        return None
    result = response.get("result") if isinstance(response, Mapping) else None
    event = result.get("event_name") if isinstance(result, Mapping) else None
    return event if isinstance(event, str) and event else None


__all__ = ["native_hook_event"]
