"""Finite, nonblocking publisher state after an original fixture failure."""

from __future__ import annotations

import time
from collections.abc import Mapping
from typing import Any


def rejected_starting_snapshot(publisher: Any) -> dict[str, object]:
    """Observe after rejection; do not retry the getter or alter publication."""
    result: dict[str, object] = {
        "capture_boundary": "after_original_starting_snapshot_rejection",
        "capture_available": False,
        "starting_snapshot_returned": False,
    }
    acquired = False
    condition = None
    try:
        condition = publisher._condition
        acquired = condition.acquire(blocking=False)
        if not acquired:
            result["capture_busy"] = True
            return result
        state: dict[str, object] = {}
        for name, field in (("publisher_acked", "_acked"), ("publisher_closed", "_closed")):
            value = getattr(publisher, field, None)
            state[name] = value if type(value) is bool else None
        epoch = getattr(publisher, "_epoch", None)
        state["publisher_epoch"] = epoch if type(epoch) is int and 0 <= epoch < 2**63 else None
        snapshot = getattr(publisher, "_snapshot", None)
        state["retained_snapshot_present"] = isinstance(snapshot, Mapping)
        if isinstance(snapshot, Mapping):
            generation, expires = snapshot.get("generation"), snapshot.get("expires_at_ms")
            state["retained_generation"] = generation if type(generation) is int and 0 <= generation < 2**63 else None
            state["retained_expired_at_observation"] = (
                expires <= int(time.time() * 1000) if type(expires) is int else None
            )
        state["last_error_present"] = getattr(publisher, "_last_error", None) is not None
        result.update(state, capture_available=True)
    except Exception:
        result["capture_failed"] = True
    finally:
        if acquired and condition is not None:
            try:
                condition.release()
            except Exception:
                result.update(capture_available=False, capture_failed=True)
    return result
