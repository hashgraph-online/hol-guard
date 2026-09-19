"""One read-only view of Cloud Review connection, consent and delivery."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from ..passive_status_store import PassiveStatusStore
from ..store import GuardStore
from .exact_cloud_review import exact_cloud_review_status

CLOUD_REVIEW_RECOVERY_KEY = "guard_cloud_review_settings_recovery"


def review_connection_binding_id(binding: dict[str, str] | None) -> str | None:
    if binding is None:
        return None
    encoded = json.dumps(binding, sort_keys=True, separators=(",", ":")).encode()
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def cloud_review_status(
    store: GuardStore | Path,
    *,
    source: str = "default",
    allow_system_keyring: bool = False,
    worker_observation: object = None,
    now: datetime | None = None,
) -> dict[str, object]:
    reader = PassiveStatusStore(store, source=source, allow_system_keyring=allow_system_keyring)
    try:
        return _project_cloud_review_status(reader, worker_observation=worker_observation, now=now)
    finally:
        reader.close()


def _project_cloud_review_status(
    store: GuardStore, *, worker_observation: object, now: datetime | None
) -> dict[str, object]:
    observed_at = now or datetime.now(timezone.utc)
    status = exact_cloud_review_status(store, now=observed_at.isoformat(), read_only=True)
    binding = store.get_review_event_oauth_binding()
    profile = store.get_cloud_sync_profile()
    binding_id = review_connection_binding_id(binding)
    delivery_binding = {key: value for key, value in binding.items() if key != "oauth_source"} if binding else None
    outbox = store.review_event_outbox_status(now=observed_at.isoformat(), **(delivery_binding or {}))
    sync_key = "guard_cloud_review_sync_state"
    if store.guard_source != "default":
        sync_key += f":{store.guard_source}"
    sync = store.get_sync_payload(sync_key)
    sync = sync if isinstance(sync, dict) else {}
    recovery = store.get_sync_payload(CLOUD_REVIEW_RECOVERY_KEY)
    recovery = recovery if isinstance(recovery, dict) and recovery.get("binding") == binding else {}
    connected = profile is not None and binding is not None
    enabled = status.get("enabled") is True
    consent_expired = status.get("reason") == "cloud_review_capability_expired"
    recovery_action = None
    if consent_expired:
        recovery_action = "hol-guard cloud-review enable --renew"
    elif connected and not enabled:
        recovery_action = "hol-guard cloud-review enable"
    worker = _current_worker_observation(
        worker_observation, binding_id=binding_id, source=store.guard_source, now=observed_at
    )
    readiness, readiness_reason = _delivery_readiness(
        connected=connected, enabled=enabled, status=status, recovery=recovery, worker=worker
    )
    pending_uploads = outbox.get("depth", 0) if binding else 0
    diagnostics = status.get("diagnostics")
    diagnostics = dict(diagnostics) if isinstance(diagnostics, dict) else {}
    # Queue history has no connection binding; fresh liveness is exposed separately.
    diagnostics["worker"] = {
        "last_delivery_error": None,
        "exact_review_route_error": None,
        "last_poll_at": None,
        "last_result_at": None,
        "state": "unavailable",
    }
    diagnostics["outbox"] = {
        "depth": pending_uploads,
        "last_delivery_error": outbox.get("last_error") if binding else None,
        "state": outbox.get("binding_state", "unknown") if binding else "unbound",
    }
    return {
        **status,
        "diagnostics": diagnostics,
        "connected": connected,
        "consent_enabled": enabled,
        "consent_expired": consent_expired,
        "disconnected": not connected,
        "recovery_action": recovery_action,
        "delivery_ready": readiness,
        "delivery_readiness_reason": readiness_reason,
        "expires_at": status.get("expires_at"),
        "workspace_id": binding["workspace_id"] if binding else None,
        "source": binding["oauth_source"] if binding else None,
        "connection_binding_id": binding_id,
        "pending_uploads": pending_uploads,
        "held_events": store.count_recoverable_unbound_review_events(),
        "isolated_events": outbox.get("quarantined_depth", 0) if binding else 0,
        "activation_error": recovery.get("error"),
        "recovery_state": "ready" if readiness is True else readiness_reason,
        "last_synced_at": (
            sync.get("last_delivery_at")
            if delivery_binding is not None and sync.get("last_delivery_binding") == delivery_binding
            else None
        ),
        "delivery_state": "unknown",  # Saved attempts have no current-connection identity binding.
        "worker": worker,
    }


def _current_worker_observation(
    value: object, *, binding_id: str | None, source: str, now: datetime
) -> dict[str, object]:
    unknown: dict[str, object] = {"running": None, "sync_running": None, "observed_at": None}
    if (
        not isinstance(value, dict)
        or binding_id is None
        or value.get("connection_binding_id") != binding_id
        or value.get("source") != source
    ):
        return unknown
    timestamp = value.get("observed_at")
    if not isinstance(timestamp, str):
        return unknown
    try:
        observed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        if observed.tzinfo is None or not 0 <= (now - observed).total_seconds() <= 5:
            return unknown
    except (TypeError, ValueError, OverflowError):
        return unknown
    return {
        "running": value.get("running") if type(value.get("running")) is bool else None,
        "sync_running": value.get("sync_running") if type(value.get("sync_running")) is bool else None,
        "observed_at": timestamp,
        "source": source,
        "connection_binding_id": binding_id,
    }


def _delivery_readiness(
    *,
    connected: bool,
    enabled: bool,
    status: dict[str, object],
    recovery: dict[str, object],
    worker: dict[str, object],
) -> tuple[bool | None, object]:
    if not connected:
        return False, "cloud_not_connected"
    if not enabled:
        return False, status.get("reason") or "cloud_review_disabled"
    if recovery.get("error"):
        return False, recovery["error"]
    values = (worker.get("running"), worker.get("sync_running"))
    if any(value is False for value in values):
        return False, "worker_restart_required"
    if all(value is True for value in values):
        return True, None
    return None, "worker_status_unavailable"
