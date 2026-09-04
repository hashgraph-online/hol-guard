"""Shared Guard Cloud first-sync failure recording for CLI and daemon."""

from __future__ import annotations

from ..store import GuardStore


def apply_guard_connect_sync_result(
    store: GuardStore,
    payload: dict[str, object],
    *,
    now: str,
    error: object,
    recorded_status: str,
    recorded_milestone: str,
    repair_message: str,
    payload_status: str | None = None,
) -> dict[str, object]:
    """Record one connect-sync failure and mirror it onto the caller payload."""

    store.record_latest_guard_connect_sync_result(
        status=recorded_status,
        milestone=recorded_milestone,
        now=now,
        reason=str(error),
    )
    update: dict[str, object] = {
        "milestone": recorded_milestone,
        "sync_succeeded": False,
        "sync_error": str(error),
        "repair_message": repair_message,
        "latest_connect_state": store.get_latest_guard_connect_state(now=now),
    }
    if payload_status is not None:
        update["status"] = payload_status
    payload.update(update)
    return payload
