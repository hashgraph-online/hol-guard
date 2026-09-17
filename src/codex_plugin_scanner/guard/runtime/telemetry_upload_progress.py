"""Durable upload progress and sanitized diagnostics for optional telemetry."""

from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta

from ..redaction import redact_sensitive_text
from ..store import GuardStore


class TelemetryProgressError(RuntimeError):
    """Remote upload progress could not be saved locally and must not be hidden."""

    def __init__(self, *, uploaded_count: int) -> None:
        super().__init__("Guard could not save telemetry upload progress. Check local storage before retrying.")
        self.uploaded_count = uploaded_count


def persist_pain_signal_cursor(store: GuardStore, *, event_id: int, uploaded_count: int, now: str) -> None:
    try:
        store.set_sync_payload("pain_signal_cursor", {"event_id": event_id}, now)
    except (OSError, sqlite3.Error) as error:
        raise TelemetryProgressError(uploaded_count=uploaded_count) from error


def record_guard_events_sync_failure(
    store: GuardStore,
    *,
    total_events: int,
    total_accepted: int,
    pending_count: int,
    error_type: str,
    message: str,
    recorded_at: str,
    retry_timeout_seconds: int,
) -> None:
    next_retry_after = (datetime.fromisoformat(recorded_at) + timedelta(seconds=retry_timeout_seconds)).isoformat()
    summary: dict[str, object] = {
        "synced_at": None,
        "status": "failed",
        "events": total_events,
        "accepted": total_accepted,
        "pending_events": pending_count,
        "error_type": error_type,
        "message": redact_sensitive_text(message),
        "retry_after_seconds": retry_timeout_seconds,
        "next_retry_after": next_retry_after,
    }
    store.set_sync_payload("guard_events_v1_summary", summary, recorded_at)
