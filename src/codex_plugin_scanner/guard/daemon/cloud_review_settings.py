"""Local, proof-gated Cloud Review setup and recovery."""

from __future__ import annotations

import sqlite3
from collections.abc import Callable
from datetime import datetime, timezone

from ..approval_gate import input_from_mapping, public_config, require_high_risk
from ..runtime.cloud_review_consent import reuse_or_issue_cloud_review_consent
from ..runtime.cloud_review_status import CLOUD_REVIEW_RECOVERY_KEY, cloud_review_status, review_connection_binding_id
from ..runtime.cloud_review_worker_readiness import cloud_review_workers_ready
from ..runtime.exact_cloud_review import (
    ExactCloudReviewError,
    disable_exact_cloud_review,
    enable_exact_cloud_review,
    exact_cloud_review_status,
)
from ..store import GuardStore

_RECOVERY_KEY = CLOUD_REVIEW_RECOVERY_KEY


class CloudReviewSettingsError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code: str = code


def cloud_review_settings_status(store: GuardStore, *, worker_observation: object = None) -> dict[str, object]:
    return {
        **cloud_review_status(store, worker_observation=worker_observation),
        "approval_gate": public_config(store.guard_home).to_dict(),
        "personal_consent_required_for_managed_admin_review": False,
        "managed_admin_authority": "workspace_admin_mfa",
        "recovery_actions": {
            "retry_delivery": "cloud-review.retry_delivery",
            "renew_consent": "cloud-review.renew_consent",
        },
    }


def change_cloud_review_settings(
    store: GuardStore,
    payload: dict[str, object],
    *,
    refresh_workers: Callable[[], dict[str, object]],
) -> dict[str, object]:
    action = payload.get("action")
    if action not in {"enable", "disable", "retry_delivery", "renew_consent"}:
        raise CloudReviewSettingsError(
            "invalid_action",
            "Choose Enable Cloud Review, retry delivery, renew consent, or Turn off Cloud Review.",
        )
    if payload.get("confirm") != f"cloud-review.{action}":
        raise CloudReviewSettingsError("confirmation_required", "Confirm this Cloud Review change.")
    if type(payload.get("include_held_requests", False)) is not bool:
        raise CloudReviewSettingsError("invalid_recovery_scope", "Choose whether to include held requests.")
    if type(payload.get("renew_consent", False)) is not bool:
        raise CloudReviewSettingsError("invalid_consent_renewal", "Choose whether to renew Cloud Review consent.")
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
        if action in {"enable", "retry_delivery", "renew_consent"}:
            if binding is None or store.get_cloud_sync_profile() is None:
                raise CloudReviewSettingsError("cloud_not_connected", "Connect Guard Cloud on this device first.")
            if (
                payload.get("workspace_id") != binding["workspace_id"]
                or payload.get("source") != binding["oauth_source"]
            ):
                raise CloudReviewSettingsError(
                    "connection_changed", "The connected workspace changed. Refresh before confirming."
                )
            if action == "retry_delivery" and exact_cloud_review_status(store).get("enabled") is not True:
                raise CloudReviewSettingsError(
                    "cloud_review_consent_required", "Enable or renew Cloud Review consent before retrying delivery."
                )
            if action == "retry_delivery" and payload.get("renew_consent") is True:
                raise CloudReviewSettingsError("invalid_consent_renewal", "Choose renew consent explicitly.")

            def issue_consent() -> dict[str, object]:
                # Retry can reuse consent, but cannot replace it after a later expiry.
                if action == "retry_delivery":
                    raise CloudReviewSettingsError(
                        "cloud_review_consent_required",
                        "Enable or renew Cloud Review consent before retrying delivery.",
                    )
                return enable_exact_cloud_review(store, issuer="local-dashboard")

            _ = reuse_or_issue_cloud_review_consent(
                store,
                issue=issue_consent,
                renew=action == "renew_consent" or payload.get("renew_consent") is True,
            )
            store.set_sync_payload(
                _RECOVERY_KEY,
                {"binding": binding, "error": "pending_request_requeue_failed"},
                datetime.now(timezone.utc).isoformat(),
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
        store.set_sync_payload(
            _RECOVERY_KEY,
            {"binding": binding, "error": activation_error or "worker_refresh_failed"},
            datetime.now(timezone.utc).isoformat(),
        )
        try:
            worker = refresh_workers()
            if action != "disable" and not cloud_review_workers_ready(worker):
                activation_error = activation_error or "worker_refresh_failed"
        except (OSError, RuntimeError, ValueError):
            worker = {"running": False, "sync_running": False}
            activation_error = activation_error or "worker_refresh_failed"
        store.set_sync_payload(
            _RECOVERY_KEY, {"binding": binding, "error": activation_error}, datetime.now(timezone.utc).isoformat()
        )
    return {
        **cloud_review_settings_status(
            store,
            worker_observation={
                **worker,
                "source": store.guard_source,
                "connection_binding_id": review_connection_binding_id(binding),
                "observed_at": datetime.now(timezone.utc).isoformat(),
            },
        ),
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
