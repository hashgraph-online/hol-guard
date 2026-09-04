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


def headless_sync_retry_summary(
    store: GuardStore,
    *,
    status: str,
    error: BaseException,
    repair: dict[str, object],
    recorded_at: str,
    record_retry: bool = False,
) -> dict[str, object]:
    if record_retry:
        store.record_latest_guard_connect_sync_result(
            status="retry_required",
            milestone="first_sync_failed",
            now=recorded_at,
            reason=str(error),
        )
    summary: dict[str, object] = {
        "status": status,
        "message": str(error),
        "authorization_repair": repair,
    }
    store.set_sync_payload("headless_app_sync_summary", summary, recorded_at)
    return summary


def failed_browser_connect_flow_state(running_state: dict[str, object], *, detail: str) -> dict[str, object]:
    return {
        **running_state,
        "state": "failed",
        "title": "Guard Cloud sign-in needs attention",
        "detail": detail,
        "poll_after_ms": None,
    }
