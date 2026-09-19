"""Retain independent receipt and telemetry results in background sync status."""

from __future__ import annotations

_TELEMETRY_FIELDS = (
    "telemetry_status",
    "pain_signals_uploaded",
    "pain_signals_upload_status",
    "pain_signals_upload_reason",
    "guard_events_v1",
    "guard_events_upload_status",
    "guard_events_upload_reason",
)


def headless_cloud_sync_summary(sync: dict[str, object], supply_chain: object) -> dict[str, object]:
    return {
        "status": "synced",
        "synced_at": sync.get("synced_at"),
        "receipts_stored": sync.get("receipts_stored", 0),
        "runtime_session_id": sync.get("runtime_session_id"),
        "runtime_session_synced_at": sync.get("runtime_session_synced_at"),
        "runtime_sessions_visible": sync.get("runtime_sessions_visible"),
        "supply_chain": supply_chain,
        **{key: sync[key] for key in _TELEMETRY_FIELDS if key in sync},
    }
