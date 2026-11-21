"""Local, proof-gated Cloud Review setup and recovery."""

from __future__ import annotations

import sqlite3
from collections.abc import Callable
from datetime import datetime, timezone

from ..approval_gate import input_from_mapping, public_config, require_high_risk
from ..native_guard_store import NativeGuardStoreUnavailable, unavailable_outbox_status
from ..runtime.exact_cloud_review import (
    ExactCloudReviewError,
    disable_exact_cloud_review,
    enable_exact_cloud_review,
    exact_cloud_review_status,
)
from ..store import GuardStore


class CloudReviewSettingsError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code: str = code


def cloud_review_reconnect_required(store: GuardStore, *, sync_reconnect_required: bool | None = None) -> bool:
    """Whether Cloud Review needs a new sign-in on this device.

    The native store decides whether the last sync error asks for one;
    ``sync_reconnect_required`` passes a decision the caller already read.
    """

    health = store.get_oauth_local_credential_health()
    if health.get("state") != "healthy":
        return True
    if sync_reconnect_required is None:
        sync_reconnect_required = store.cloud_review_settings_state(binding=None)["sync_reconnect_required"]
    return sync_reconnect_required is True


def cloud_review_settings_status(store: GuardStore) -> dict[str, object]:
    status = exact_cloud_review_status(store)
    outbox_unavailable: str | None = None
    try:
        binding = store.get_review_event_oauth_binding()
        delivery_binding = {key: value for key, value in binding.items() if key != "oauth_source"} if binding else None
        outbox = store.review_event_outbox_status(
            now=datetime.now(timezone.utc).isoformat(),
            **(delivery_binding or {}),
        )
        held_events = store.count_recoverable_unbound_review_events()
    except NativeGuardStoreUnavailable as error:
        binding, delivery_binding = None, None
        outbox = unavailable_outbox_status(error)
        outbox_unavailable = error.reason
        held_events = 0
    profile = store.get_cloud_sync_profile()
    rows = store.cloud_review_settings_state(binding=binding)
    sync = rows["sync"]
    connected = profile is not None and binding is not None
    return {
        "enabled": status.get("enabled") is True,
        "connected": connected,
        "reconnect_required": connected
        and cloud_review_reconnect_required(store, sync_reconnect_required=rows["sync_reconnect_required"]),
        "reason": status.get("reason"),
        "expires_at": status.get("expires_at"),
        "workspace_id": binding["workspace_id"] if binding else None,
        "source": binding["oauth_source"] if binding else None,
        "pending_uploads": outbox.get("depth", 0) if binding else 0,
        "held_events": held_events,
        "isolated_events": outbox.get("quarantined_depth", 0),
        "activation_error": rows["recovery_error"],
        "last_synced_at": (
            sync.get("last_delivery_at")
            if delivery_binding is not None and sync.get("last_delivery_binding") == delivery_binding
            else None
        ),
        "delivery_state": sync.get("state", "idle"),
        "approval_gate": public_config(store.guard_home).to_dict(),
        "outbox_available": outbox_unavailable is None,
        "outbox_unavailable_reason": outbox_unavailable,
    }


def change_cloud_review_settings(
    store: GuardStore,
    payload: dict[str, object],
    *,
    refresh_workers: Callable[[], dict[str, object]],
) -> dict[str, object]:
    action = payload.get("action")
    if action not in {"enable", "disable"}:
        raise CloudReviewSettingsError("invalid_action", "Choose Enable Cloud Review or Turn off Cloud Review.")
    if payload.get("confirm") != f"cloud-review.{action}":
        raise CloudReviewSettingsError("confirmation_required", "Confirm this Cloud Review change.")
    if type(payload.get("include_held_requests", False)) is not bool:
        raise CloudReviewSettingsError("invalid_recovery_scope", "Choose whether to include held requests.")
    _ = require_high_risk(
        store.guard_home,
        purpose="protection_lifecycle",
        approval_gate_input=input_from_mapping(payload),
        action=f"cloud-review.{action}",
        scope="local-protection",
        subject="exact-cloud-review",
    )
    requeued = 0
    adopted = 0
    activation_error = None
    with store.hold_oauth_credential_lock():
        binding = store.get_review_event_oauth_binding()
        if action == "enable":
            if binding is None or store.get_cloud_sync_profile() is None:
                raise CloudReviewSettingsError("cloud_not_connected", "Connect Guard Cloud on this device first.")
            if (
                payload.get("workspace_id") != binding["workspace_id"]
                or payload.get("source") != binding["oauth_source"]
            ):
                raise CloudReviewSettingsError(
                    "connection_changed", "The connected workspace changed. Refresh before confirming."
                )
            _ = enable_exact_cloud_review(store, issuer="local-dashboard")
            store.record_cloud_review_recovery(
                binding=binding, error="pending_request_requeue_failed", now=datetime.now(timezone.utc).isoformat()
            )
            try:
                if payload.get("include_held_requests") is True:
                    adopted = store.reassign_quarantined_review_events(
                        approved_source=binding["oauth_source"],
                        approved_workspace_id=binding["workspace_id"],
                        only_unbound=True,
                    )
                requeued = store.requeue_pending_review_events(
                    changed_at=datetime.now(timezone.utc).isoformat(), require_binding=True
                )
            except (sqlite3.Error, ValueError):
                activation_error = "pending_request_requeue_failed"
        else:
            _ = disable_exact_cloud_review(store, issuer="local-dashboard")
        store.record_cloud_review_recovery(
            binding=binding,
            error=activation_error or "worker_refresh_failed",
            now=datetime.now(timezone.utc).isoformat(),
        )
        try:
            worker = refresh_workers()
            if action == "enable" and (worker.get("running") is not True or worker.get("sync_running") is not True):
                activation_error = activation_error or "worker_refresh_failed"
        except (OSError, RuntimeError, ValueError):
            worker = {"running": False, "sync_running": False}
            activation_error = activation_error or "worker_refresh_failed"
        store.record_cloud_review_recovery(
            binding=binding, error=activation_error, now=datetime.now(timezone.utc).isoformat()
        )
    return {
        **cloud_review_settings_status(store),
        "pending_requests_requeued": requeued,
        "held_events_recovered": adopted,
        "activation_error": activation_error,
        "worker": worker,
    }


__all__ = [
    "CloudReviewSettingsError",
    "ExactCloudReviewError",
    "change_cloud_review_settings",
    "cloud_review_settings_status",
]
