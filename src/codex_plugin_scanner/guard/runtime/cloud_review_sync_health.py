"""Worker liveness and delivery status for Cloud Review sync."""

from __future__ import annotations

from datetime import datetime, timezone

from ..store import GuardStore
from .cloud_review_event_delivery import CLOUD_REVIEW_EVENT_PROTOCOL_VERSION


def classify_cloud_review_worker(
    state: dict[str, object],
    *,
    sync_configured: bool,
    now: datetime | None = None,
) -> str:
    """Distinguish a dormant, missing, dead, failing, or live sync worker.

    The dead threshold is three configured poll intervals. A missing, future,
    or unparsable heartbeat stays missing or unknown instead of being reported
    as healthy.
    """

    if not sync_configured:
        return "dormant"
    observed = now or datetime.now(timezone.utc)
    raw = state.get("last_worker_heartbeat_at")
    if not isinstance(raw, str) or not raw.strip():
        return "missing"
    try:
        seen = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return "unknown"
    if seen.tzinfo is None:
        return "unknown"
    age = (observed - seen.astimezone(timezone.utc)).total_seconds()
    if age < 0:
        return "unknown"
    from .cloud_review_sync_worker import configured_cloud_review_poll_seconds

    stored = state.get("worker_poll_seconds")
    poll = float(stored) if isinstance(stored, (int, float)) and stored > 0 else configured_cloud_review_poll_seconds()
    if age > poll * 3:
        return "dead"
    if state.get("state") == "error":
        return "failing"
    return "alive"


def record_cloud_review_worker_heartbeat(
    store: GuardStore,
    *,
    now: str | None = None,
    poll_seconds: float | None = None,
) -> None:
    """Persist one worker liveness mark without changing delivery cursors."""

    from .cloud_review_sync import _load_sync_state, _now, _save_sync_state

    state = _load_sync_state(store)
    state["last_worker_heartbeat_at"] = now or _now()
    if poll_seconds is not None:
        state["worker_poll_seconds"] = float(poll_seconds)
    _save_sync_state(store, state)


def cloud_review_sync_status(store: GuardStore) -> dict[str, object]:
    """Return Cloud Review outbox and delivery health."""

    from .cloud_review_sync import _load_sync_state, _now

    state = _load_sync_state(store)
    profile = store.get_cloud_sync_profile()
    workspace_id = profile.get("workspace_id") if isinstance(profile, dict) else None
    binding = store.get_review_event_oauth_binding()
    if binding is not None:
        outbox = store.review_event_outbox_status(
            now=_now(),
            oauth_subject_hash=binding["oauth_subject_hash"],
            workspace_id=binding["workspace_id"],
            machine_id=binding["machine_id"],
            machine_installation_id=binding["machine_installation_id"],
        )
    else:
        outbox = store.review_event_outbox_status(
            now=_now(),
            workspace_id=workspace_id,
        )
    sync_configured = isinstance(profile, dict) and bool(profile.get("workspace_id")) and bool(profile.get("sync_url"))
    return {
        "state": state.get("state") or "not_configured",
        "worker": classify_cloud_review_worker(state, sync_configured=sync_configured),
        "last_sync_at": state.get("last_sync_at"),
        "last_success_at": state.get("last_success_at"),
        "last_error": state.get("last_error"),
        "synced_count": state.get("synced_count", 0),
        "rejected_count": state.get("rejected_count", 0),
        "outbox": outbox,
        "oauth_source": store.guard_source,
        "protocol_version": CLOUD_REVIEW_EVENT_PROTOCOL_VERSION,
        "protocolVersion": CLOUD_REVIEW_EVENT_PROTOCOL_VERSION,
    }
