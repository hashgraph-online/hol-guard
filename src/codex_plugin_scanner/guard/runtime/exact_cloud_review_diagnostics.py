"""Read-only diagnostics for the locally consented exact review worker."""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone


def enrich_exact_cloud_review_status(store, status: dict[str, object]) -> dict[str, object]:
    """Expose the local prerequisites without leaking OAuth credential material."""

    result = dict(status)
    oauth_health = _oauth_health(store)
    queue_state = _queue_state(store)
    workspace_id = result.get("workspace_id")
    outbox = _outbox_status(store, workspace_id if isinstance(workspace_id, str) else None)
    result["diagnostics"] = {
        "capability": {"valid": bool(result.get("capability_valid")), "reason": result.get("reason")},
        "oauth": oauth_health,
        "outbox": outbox,
        "worker": {
            "last_delivery_error": queue_state.get("exact_review_route_error") or queue_state.get("last_error"),
            "exact_review_route_error": queue_state.get("exact_review_route_error"),
            "last_poll_at": queue_state.get("last_poll_at"),
            "last_result_at": queue_state.get("last_result_at"),
            "state": queue_state.get("state", "idle"),
        },
    }
    return result


def _oauth_health(store) -> dict[str, object]:
    try:
        health = store.get_oauth_local_credential_health()
    except (AttributeError, OSError, RuntimeError, ValueError, sqlite3.Error):
        return {"configured": False, "state": "unavailable"}
    return {
        "configured": bool(health.get("configured")) if isinstance(health, dict) else False,
        "state": health.get("state", "unavailable") if isinstance(health, dict) else "unavailable",
    }


def _queue_state(store) -> dict[str, object]:
    try:
        state = store.get_sync_payload("guard_command_queue_state")
    except (AttributeError, OSError, RuntimeError, ValueError, sqlite3.Error):
        return {}
    return dict(state) if isinstance(state, dict) else {}


def _outbox_status(store, workspace_id: str | None) -> dict[str, object]:
    try:
        status = store.review_event_outbox_status(now=datetime.now(timezone.utc).isoformat(), workspace_id=workspace_id)
    except (AttributeError, OSError, RuntimeError, ValueError, sqlite3.Error):
        return {"state": "unavailable"}
    if not isinstance(status, dict):
        return {"state": "unavailable"}
    return {
        "depth": status.get("depth", 0),
        "last_delivery_error": status.get("last_error"),
        "state": status.get("binding_state", "unknown"),
    }
