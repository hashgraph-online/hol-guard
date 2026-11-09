"""One pass of each daemon background job, run behind ``desktop library-call``.

The native daemon owns the schedule: it calls ``worker.<job>`` once per tick
and waits ``interval`` after a pass that succeeded or ``backoff`` after one
that did not. Each call answers ``{"ok": bool}`` plus what the pass reports.
"""

from __future__ import annotations

from collections.abc import Mapping
from contextlib import suppress
from datetime import datetime, timezone
from typing import Any

from ..store import GuardStore


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def cloud_sync(store: GuardStore, args: Mapping[str, Any]) -> dict[str, object]:
    """Syncs receipts and supply-chain state with Guard Cloud."""

    del args
    from ..daemon.server_control_cloud_sync import _run_headless_cloud_sync

    summary = _run_headless_cloud_sync(store=store)
    status = str(summary.get("status") or "")
    return {"ok": status == "synced", "status": status}


def bundle_refresh(store: GuardStore, args: Mapping[str, Any]) -> dict[str, object]:
    """Refreshes the supply-chain bundle, then the network-protection bundle."""

    del args
    from ..runtime.runner import (
        GuardSyncAuthorizationExpiredError,
        GuardSyncNotConfiguredError,
        sync_network_protection_bundle_best_effort,
        sync_supply_chain_bundle,
    )

    refreshed_at = _now()
    payload: dict[str, object]
    try:
        payload = {**sync_supply_chain_bundle(store), "status": "synced"}
    except GuardSyncAuthorizationExpiredError as error:
        payload = {"status": "auth_expired", "refreshed_at": refreshed_at, "message": str(error)}
    except GuardSyncNotConfiguredError:
        payload = {"status": "not_configured", "refreshed_at": refreshed_at}
    except Exception as error:
        payload = {"error": str(error), "refreshed_at": refreshed_at, "status": "error"}
    store.set_sync_payload("supply_chain_bundle_daemon", payload, refreshed_at)
    # Separate endpoint: refresh it whether or not the supply-chain bundle synced.
    sync_network_protection_bundle_best_effort(store)
    return {"ok": payload["status"] == "synced", "status": payload["status"]}


def plugin_telemetry(store: GuardStore, args: Mapping[str, Any]) -> dict[str, object]:
    """Sends the opted-in weekly plugin install report; a no-op until opt-in."""

    del args
    from ..plugin_telemetry.report import PluginTelemetryError, send_if_due

    try:
        send_if_due(store.guard_home)
    except PluginTelemetryError:
        return {"ok": False}
    return {"ok": True}


def maintain_activity(store: GuardStore, args: Mapping[str, Any]) -> dict[str, object]:
    """Trims command activity and storage; ``ok`` is false while storage work remains."""

    del args
    from ..config import load_guard_config
    from ..store_storage_maintenance import DEFAULT_GUARD_EVENT_LIMIT, DEFAULT_RECEIPT_DETAIL_LIMIT

    now = datetime.now(timezone.utc)
    try:
        config = load_guard_config(store.guard_home)
        store.maintain_command_activity(now=now, detail_retain_days=config.evidence_retain_days)
    except Exception:
        with suppress(Exception):
            store.record_command_activity_persistence_failure(error_code="maintenance_failed", occurred_at=now)
    try:
        config = load_guard_config(store.guard_home)
        result = store.maintain_storage(
            now=datetime.now(timezone.utc),
            detail_retain_days=config.evidence_retain_days,
            receipt_detail_limit=(
                config.receipt_detail_limit if config.receipt_detail_limit is not None else DEFAULT_RECEIPT_DETAIL_LIMIT
            ),
            guard_event_limit=(
                config.guard_event_limit if config.guard_event_limit is not None else DEFAULT_GUARD_EVENT_LIMIT
            ),
        )
    except Exception:
        return {"ok": False}
    return {"ok": bool(result.completed)}


def extension_catalog(store: GuardStore, args: Mapping[str, Any]) -> dict[str, object]:
    """Observes active command-pack security, requests discovery, cleans the pack cache."""

    del args
    from ..catalog_delivery import lifecycle
    from ..catalog_delivery.active_security import observe
    from ..catalog_delivery.cache_io import cleanup
    from ..catalog_delivery.discovery import request_refresh

    with lifecycle.session():
        try:
            observe(store)
        finally:
            request_refresh(store.guard_home, store=store)
        cleanup(store)
    return {"ok": True}


def runtime_heartbeat(store: GuardStore, args: Mapping[str, Any]) -> dict[str, object]:
    """Records that the daemon at ``host:port`` is alive."""

    from ..library_calls import LibraryCallError

    session_id = args.get("session_id")
    host = args.get("host")
    port = args.get("port")
    started_at = args.get("started_at")
    if (
        not isinstance(session_id, str)
        or not isinstance(host, str)
        or not isinstance(port, int)
        or isinstance(port, bool)
        or not isinstance(started_at, str)
    ):
        raise LibraryCallError("invalid_arguments")
    store.upsert_runtime_state(
        session_id=session_id,
        daemon_host=host,
        daemon_port=port,
        started_at=started_at,
        last_heartbeat_at=_now(),
    )
    return {"ok": True}


def idle_holds(store: GuardStore, args: Mapping[str, Any]) -> dict[str, object]:
    """Whether durable work keeps an idle daemon alive: a pending review or queued Cloud events."""

    del args
    try:
        pending = store.list_approval_requests(status="pending", limit=1)
    except Exception:
        # Pending rows stay durable in guard.db; an unreadable queue must not
        # pin the daemon alive.
        pending = []
    outbox_depth = 0
    try:
        profile = store.get_cloud_sync_profile()
        workspace_id = profile.get("workspace_id") if isinstance(profile, dict) else None
        if workspace_id is not None:
            depth = store.review_event_outbox_status(now=_now(), workspace_id=workspace_id)["depth"]
            outbox_depth = depth if isinstance(depth, int) else 0
    except Exception:
        # Queued events stay durable in guard.db; do not pin the daemon alive.
        outbox_depth = 0
    return {"ok": True, "hold": bool(pending) or outbox_depth > 0}


WORKER_CALLS = {
    "worker.cloud_sync": cloud_sync,
    "worker.bundle_refresh": bundle_refresh,
    "worker.plugin_telemetry": plugin_telemetry,
    "worker.maintain_activity": maintain_activity,
    "worker.extension_catalog": extension_catalog,
    "worker.runtime_heartbeat": runtime_heartbeat,
    "worker.idle_holds": idle_holds,
}
