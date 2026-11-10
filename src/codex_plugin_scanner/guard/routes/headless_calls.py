"""Guard library steps the native daemon's app, runtime and local CLI routes run.

The native daemon owns ``POST /v1/apps/{action}``, ``GET /v1/runtime`` and
``GET /v1/local-clis``: the action table, every refusal, the app state a
finished action reports, the reconnect summary, the operator health verdict
and every reply. Each call here is one library step it cannot take natively
yet and reports its outcome as data.
"""

from __future__ import annotations

import platform
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from ...version import __version__
from ..adapters import get_adapter
from ..adapters.base import HarnessContext
from ..approval_gate import ApprovalGateError
from ..cli.install_commands import (
    apply_managed_install,
    build_harness_verification,
    uninstall_confirmation_token,
)
from ..harness_disconnect_gate import require_harness_disconnect_gate
from ..headless_receipts import record_headless_receipt
from ..native_hook_evidence_writer import unreachable_writer_stats
from ..store import GuardStore
from .control_host import control_server


def _text(value: object) -> str | None:
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _payload(args: Mapping[str, Any]) -> dict[str, object]:
    payload = args.get("payload")
    return dict(payload) if isinstance(payload, dict) else {}


def _cursor_surface(payload: Mapping[str, object]) -> str | None:
    surface = _text(payload.get("surface")) or _text(payload.get("editor_or_cli"))
    if surface is None:
        return None
    if surface not in {"editor", "cli"}:
        raise ValueError("invalid_cursor_surface")
    return surface


def _managed_action(
    store: GuardStore,
    harness: str,
    action: str,
    payload: dict[str, object],
    context: HarnessContext,
    surface: str | None,
) -> dict[str, object]:
    if action == "uninstall":
        confirmation = _text(payload.get("confirmation_phrase")) or _text(payload.get("confirmation_token"))
        if confirmation != uninstall_confirmation_token(harness):
            raise ValueError("confirmation_required")
        require_harness_disconnect_gate(store.guard_home, payload, harness=harness)
    return apply_managed_install(
        "uninstall" if action == "uninstall" else "install",
        harness,
        False,
        context,
        store,
        _text(payload.get("workspace_id")),
        _now(),
        surface=surface,
    )


def _now() -> str:
    from ..daemon.server_common import _now as now

    return now()


def _latest_cloud_sync(store: GuardStore) -> dict[str, object]:
    latest = store.get_sync_payload("headless_app_sync_summary")
    if not isinstance(latest, dict):
        latest = store.get_sync_payload("sync_summary")
    return dict(latest) if isinstance(latest, dict) else {}


def _reconnect_facts(store: GuardStore) -> dict[str, object]:
    summary = store.get_sync_payload("runtime_session_summary")
    runtime = summary if isinstance(summary, dict) else {}
    return {
        "latest_cloud_sync": _latest_cloud_sync(store),
        "last_runtime_sync_at": _text(runtime.get("runtime_session_synced_at")) or _text(runtime.get("synced_at")),
        "local_guard_online_at": _text(runtime.get("local_guard_online_at")),
        "daemon_id": _text(runtime.get("runtime_device_id")),
        "daemon_version": __version__,
        "hostname": platform.node() or None,
    }


def run_app_action(store: GuardStore, args: Mapping[str, Any]) -> dict[str, object]:
    """Runs one app action, records its receipt and queues the Cloud sync."""

    from ..daemon.server_control_cloud_sync import (
        _managed_controls_publish_for,
        _queue_headless_cloud_sync_with_optional_publish,
    )

    payload = _payload(args)
    operation = str(args.get("operation") or "")
    harness_action = str(args.get("harness_action") or "")
    try:
        adapter = get_adapter(str(args.get("harness") or ""))
    except ValueError:
        return {"error": "unknown_harness"}
    try:
        surface = _cursor_surface(payload) if adapter.harness == "cursor" else None
    except ValueError:
        return {"error": "invalid_cursor_surface"}
    context = HarnessContext(home_dir=Path.home().resolve(), workspace_dir=None, guard_home=store.guard_home)
    try:
        if harness_action == "verify":
            result = build_harness_verification(
                adapter.harness,
                context,
                store,
                surface=surface,
                action="status" if args.get("action_path") == "status" else "test",
            )
        else:
            result = _managed_action(store, adapter.harness, harness_action, payload, context, surface)
    except ApprovalGateError as error:
        return {"reply": [error.status, error.to_payload()]}
    except ValueError as error:
        return {"error": str(error)}
    location_id = _text(payload.get("location_id")) or _text(payload.get("locationId"))
    receipt = record_headless_receipt(
        store,
        harness=adapter.harness,
        operation=operation,
        payload=payload,
        result=result,
        location_id=location_id,
        workspace_id=_text(payload.get("workspace_id")),
        cloud_sync={"status": "pending"},
    )
    with control_server(store, args) as server:
        cloud_sync = _queue_headless_cloud_sync_with_optional_publish(
            store=store, managed_controls_publish=_managed_controls_publish_for(server)
        )
    receipt["cloud_sync"] = cloud_sync
    return {
        "harness": adapter.harness,
        "result": result,
        "receipt": receipt,
        "cloud_sync": cloud_sync,
        "location_id": location_id,
        "reconnect": _reconnect_facts(store),
    }


def runtime_snapshot(store: GuardStore, args: Mapping[str, Any]) -> dict[str, object]:
    """The runtime snapshot and the facts the operator health verdict reads."""

    from ..approvals import build_runtime_snapshot
    from ..config import load_guard_config
    from ..daemon.command_activity_health_repair import auto_repair_command_activity_health_if_degraded
    from ..daemon.server_control_cloud_sync import _managed_controls_publish_for, _maybe_queue_first_cloud_sync
    from ..daemon.server_control_health import cached_containment_health
    from ..models import format_local_http_origin
    from ..native_daemon_manage import current_guard_daemon_runtime_fingerprint
    from ..runtime.containment_health import probe_containment_health

    with control_server(store, args) as server:
        _maybe_queue_first_cloud_sync(store=store, managed_controls_publish=_managed_controls_publish_for(server))
        auto_repair_command_activity_health_if_degraded(store)
        containment = cached_containment_health(
            server,
            force_refresh=False,
            probe=lambda: probe_containment_health(
                daemon_fingerprint=current_guard_daemon_runtime_fingerprint(),
                guard_home=store.guard_home,
            ).to_dict(),
        )
        active_request_id = args.get("active_request_id")
        snapshot = build_runtime_snapshot(
            store=store,
            approval_center_url=format_local_http_origin(server.daemon_host(), server.daemon_port()),
            active_request_id=active_request_id if isinstance(active_request_id, str) else None,
            include_items=args.get("include_items") is not False,
            receipt_limit=25 if args.get("include_receipts") is not False else 0,
            containment_health=containment,
            serving_runtime={
                "session_id": server.runtime_session_id,
                "daemon_host": server.runtime_host,
                "daemon_port": server.daemon_port(),
                "started_at": server.runtime_started_at,
                "last_heartbeat_at": _now(),
            },
        )
        try:
            evidence_writer = server.runtime_hook_evidence_writer.stats()
        except Exception:
            evidence_writer = unreachable_writer_stats()
    activity = store.get_command_activity_persistence_health()
    return {
        "snapshot": snapshot,
        "security_level": load_guard_config(store.guard_home).security_level,
        "evidence_writer": dict(evidence_writer),
        "activity": {
            "persistence_error_count": activity.persistence_error_count,
            "last_error_code": activity.last_error_code,
        },
    }


def local_clis(store: GuardStore, args: Mapping[str, Any]) -> dict[str, object]:
    """The custom extension list, filtered to one connector identity when named."""

    identity = args.get("identity")
    with control_server(store, args) as server:
        try:
            api = server.local_cli_api
            payload = api.list_items() if not isinstance(identity, str) else api.list_items(identity_hash=identity)
        except Exception as error:
            server.diagnostics.record_exception("local_cli_list_failed", detail=type(error).__name__)
            return {"payload": None}
    return {"payload": payload if isinstance(payload, dict) else None}


HEADLESS_CALLS = {
    "headless.app_action": run_app_action,
    "runtime.snapshot": runtime_snapshot,
    "local_clis.list": local_clis,
}
