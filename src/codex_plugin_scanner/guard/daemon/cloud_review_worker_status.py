"""Observe current worker threads without starting, refreshing or stopping them."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING

from ..runtime.cloud_review_status import review_connection_binding_id
from ..store import GuardStore

if TYPE_CHECKING:
    from .server import GuardDaemonServer


def observe_cloud_review_workers(store: GuardStore, lifecycle: GuardDaemonServer | None) -> dict[str, object] | None:
    if lifecycle is None or not lifecycle._finish_service_lock.acquire(blocking=False):
        return None
    try:
        if lifecycle._server.store.guard_source != store.guard_source:
            return None
        available = lifecycle._owned_service_ready and not lifecycle._shutdown_started.is_set()
        decision = lifecycle._command_queue_worker
        events = lifecycle._cloud_review_sync_worker
        return {
            "running": bool(available and decision and decision.thread.is_alive() and not decision.stop_event.is_set()),
            "sync_running": bool(available and events and events.thread.is_alive() and not events.stop_event.is_set()),
            "source": store.guard_source,
            "connection_binding_id": review_connection_binding_id(store.get_review_event_oauth_binding()),
            "observed_at": datetime.now(timezone.utc).isoformat(),
        }
    finally:
        lifecycle._finish_service_lock.release()
