"""One pass of each daemon background job, run behind ``desktop library-call``.

The native daemon owns the schedule: it calls ``worker.<job>`` once per tick
and waits ``interval`` after a pass that succeeded or ``backoff`` after one
that did not. Each call answers ``{"ok": bool}`` plus what the pass reports.
The runtime heartbeat, the idle-shutdown hold and storage maintenance run in
the native daemon itself.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..store import GuardStore


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def cloud_sync(store: GuardStore, args: Mapping[str, Any]) -> dict[str, object]:
    """Syncs receipts and supply-chain state with Guard Cloud."""

    del args
    from ..cloud_control.server_control_cloud_sync import _run_headless_cloud_sync

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
        _refresh_extension_controls(store)
    # A cleanup that fails while a discovery refresh is still publishing is
    # retried on the next pass, as the daemon's refresh loop did.
    try:
        with lifecycle.session():
            cleanup(store)
    except Exception:
        return {"ok": False}
    return {"ok": True}


def _refresh_extension_controls(store: GuardStore) -> None:
    """Refresh the extension-control service this process already serves.

    The native daemon runs this tick in its resident library process, which
    keeps that service between requests. A process that has not served one
    builds none here.
    """

    from ..extension_control_host import existing_host
    from ..runtime_health.background_diagnostics import failure_detail, record_background_event

    host = existing_host(store)
    if host is None:
        return
    try:
        host.refresh()
    except Exception as error:
        record_background_event("extension_control_refresh_failed", failure_detail(error))
    host.api.expire_prepared_cache_leases()


def reconcile_artifacts(store: GuardStore, args: Mapping[str, Any]) -> dict[str, object]:
    """Brings Guard-owned artifacts in line with the active runtime before the daemon reports ready."""

    from ..runtime_artifact_reconciliation import reconcile_runtime_artifacts

    home = args.get("home")
    result = reconcile_runtime_artifacts(store, home_dir=Path(home) if isinstance(home, str) and home else None)
    return {
        "ok": True,
        "healthy": result.healthy,
        "repaired_harnesses": list(result.repaired_harnesses),
        "failed_harnesses": list(result.failed_harnesses),
    }


def aibom_inventory(store: GuardStore, args: Mapping[str, Any]) -> dict[str, object]:
    """Syncs the AIBOM snapshots for the bound workspace, or the user-wide inventory without one."""

    del args
    from ..aibom_cli import (
        _AIBOM_AUTO_SYNC_INTERVAL_SECONDS,
        remember_user_inventory_if_due,
        sync_aibom_snapshots_if_due,
    )
    from ..runtime.runner import (
        GuardSyncAuthorizationExpiredError,
        GuardSyncNotConfiguredError,
        _resolve_guard_sync_auth_context,
    )

    refreshed_at = _now()
    min_interval = max(int(_AIBOM_AUTO_SYNC_INTERVAL_SECONDS), 1)
    payload = store.get_sync_payload("aibom_inventory_context")
    current_workspace_id = store.get_cloud_workspace_id()
    bound = (
        payload
        if current_workspace_id is not None
        and isinstance(payload, dict)
        and payload.get("workspace_id") == current_workspace_id
        else {}
    )

    def _path(value: object) -> Path | None:
        return Path(value).expanduser() if isinstance(value, str) and value.strip() else None

    home_dir = _path(bound.get("home_dir"))
    workspace_dir = _path(bound.get("workspace_dir"))
    try:
        if workspace_dir is None:
            # Without a workspace the cloud snapshot is left alone; the
            # user-wide scan still feeds fleet posture inventory.
            try:
                user_inventory: dict[str, object] = remember_user_inventory_if_due(
                    store,
                    generated_at=refreshed_at,
                    min_interval_seconds=min_interval,
                    home_dir=home_dir,
                )
            except Exception as error:
                user_inventory = {"collected": False, "error": str(error)}
            store.set_sync_payload(
                "aibom_inventory_daemon",
                {
                    "status": "missing_workspace_context",
                    "reason": "missing_workspace_context",
                    "skipped": True,
                    "refreshed_at": refreshed_at,
                    "user_inventory": user_inventory,
                },
                refreshed_at,
            )
            return {"ok": False, "status": "missing_workspace_context"}
        auth_context = _resolve_guard_sync_auth_context(store)
        with store.hold_cloud_sync_lock():
            summary = sync_aibom_snapshots_if_due(
                store,
                generated_at=refreshed_at,
                min_interval_seconds=min_interval,
                auth_context=auth_context,
                expected_workspace_id=current_workspace_id,
                home_dir=home_dir,
                workspace_dir=workspace_dir,
            )
        has_error = bool(summary.get("error"))
        status = (
            "error"
            if has_error
            else "synced"
            if summary.get("synced") is True
            else str(summary.get("reason") or "skipped")
        )
        store.set_sync_payload(
            "aibom_inventory_daemon", {**summary, "status": status, "refreshed_at": refreshed_at}, refreshed_at
        )
        return {"ok": not has_error and status != "not_configured", "status": status}
    except GuardSyncAuthorizationExpiredError as error:
        record: dict[str, object] = {"status": "auth_expired", "refreshed_at": refreshed_at, "message": str(error)}
    except GuardSyncNotConfiguredError:
        record = {"status": "not_configured", "refreshed_at": refreshed_at}
    except Exception as error:
        record = {"error": str(error), "refreshed_at": refreshed_at, "status": "error"}
    store.set_sync_payload("aibom_inventory_daemon", record, refreshed_at)
    return {"ok": False, "status": record["status"]}


def onefile_reclaim(store: GuardStore, args: Mapping[str, Any]) -> dict[str, object]:
    """Reclaims orphaned one-file extraction directories left by earlier frozen runs."""

    del store, args
    import sys
    import tempfile

    from ..onefile_extraction import reclaim_orphaned_extraction_dirs

    if not getattr(sys, "frozen", False):
        return {"ok": True, "skipped": True}
    # Directories still open, this call's own among them, are left in place.
    reclaim_orphaned_extraction_dirs(
        temp_root=Path(tempfile.gettempdir()),
        current_meipass=getattr(sys, "_MEIPASS", None),
        now=datetime.now(timezone.utc),
        scan_open_paths=True,
    )
    return {"ok": True}


WORKER_CALLS = {
    "worker.cloud_sync": cloud_sync,
    "worker.bundle_refresh": bundle_refresh,
    "worker.plugin_telemetry": plugin_telemetry,
    "worker.extension_catalog": extension_catalog,
    "worker.reconcile_artifacts": reconcile_artifacts,
    "worker.aibom_inventory": aibom_inventory,
    "worker.onefile_reclaim": onefile_reclaim,
}
