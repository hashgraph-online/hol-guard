"""Privacy-safe local export for policy delivery incidents."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import cast

from .cli.desktop_policy_status import read_policy_application_evidence
from .passive_status_store import PassiveStatusStore
from .policy_bundle_parser import policy_bundle_rejection_message
from .policy_runtime_error_catalog import explain_policy_runtime_error, policy_runtime_error_catalog
from .runtime.cloud_review_status import _project_cloud_review_status
from .store import GuardStore

_SECRET_MARKERS = (
    "refresh-token",
    "refresh_token",
    "dpop_private_key",
    "private_key",
    "access_token",
    "BEGIN PRIVATE KEY",
    "canary-secret",
    "tokensecret",
)


def build_policy_support_export(
    store: GuardStore | Path,
    *,
    now: str | None = None,
    source: str = "default",
    allow_system_keyring: bool = False,
) -> dict[str, object]:
    observed_at = datetime.fromisoformat(now.replace("Z", "+00:00")) if now else datetime.now(timezone.utc)
    reader = PassiveStatusStore(store, source=source, allow_system_keyring=allow_system_keyring)
    try:
        return _build_support_export(reader, observed_at=observed_at)
    finally:
        reader.close()


def _build_support_export(store: GuardStore, *, observed_at: datetime) -> dict[str, object]:
    review = _project_cloud_review_status(store, worker_observation=None, now=observed_at)
    settings = review
    policy_evidence = read_policy_application_evidence(store)
    bundle = store.get_sync_payload("policy_bundle_last_good")
    last_error = store.get_sync_payload("policy_bundle_last_error")
    sync_summary = store.get_sync_payload("sync_summary")
    binding = store.get_review_event_oauth_binding() or {}
    error_code = None
    if isinstance(last_error, dict):
        reason = last_error.get("reason")
        if isinstance(reason, str):
            error_code = _public_error_code(reason)
    if error_code is None and isinstance(review.get("reason"), str):
        error_code = _public_error_code(review["reason"])
    explained = explain_policy_runtime_error(error_code or "policy_support_export")
    export: dict[str, object] = {
        "kind": "hol-guard-policy-support-export.v1",
        "observed_at": observed_at.isoformat(),
        "failure_classes": {
            "auth": explained["code"] in {"cloud_review_capability_revoked", "cloud_review_capability_missing"}
            or str(review.get("reason") or "").startswith("cloud_review_"),
            "invalid_policy": isinstance(last_error, dict),
            "wrong_target": explained["code"] == "remote_exact_wrong_target",
            "runtime_publication": isinstance(sync_summary, dict)
            and sync_summary.get("policy_application_status") == "rejected",
            "continuation": settings.get("delivery_state") not in {None, "idle", "unknown"},
        },
        "policy": _bundle_identity(bundle, last_error, policy_evidence),
        "cloud_review": {
            "enabled": review.get("enabled"),
            "reason": _public_error_code(review.get("reason")),
            "workspace_id": review.get("workspace_id") or settings.get("workspace_id"),
            "personal_consent_required_for_managed_admin_review": False,
            "pending_uploads": settings.get("pending_uploads"),
            "held_events": settings.get("held_events"),
            "isolated_events": settings.get("isolated_events"),
            "activation_error": _public_error_code(settings.get("activation_error")),
            "delivery_state": settings.get("delivery_state"),
            "diagnostics": _public_diagnostics(review.get("diagnostics")),
        },
        "sync": _public_sync_summary(sync_summary),
        "identity": {
            "workspace_id": binding.get("workspace_id"),
            "machine_id": binding.get("machine_id"),
            "machine_installation_id": binding.get("machine_installation_id"),
            "oauth_subject_hash": binding.get("oauth_subject_hash"),
        },
        "error": explained,
        "error_catalog": [dict(entry) for entry in policy_runtime_error_catalog()],
    }
    dumped = repr(export)
    if any(marker in dumped for marker in _SECRET_MARKERS):
        raise RuntimeError("policy_support_export_secret_leak")
    return export


def _bundle_identity(bundle: object, last_error: object, evidence: dict[str, object]) -> dict[str, object]:
    identity: dict[str, object] = {"applied": evidence.get("appliedRevision") is not None}
    retained = (
        isinstance(bundle, dict)
        and evidence.get("policyBundleHash") is not None
        and bundle.get("bundleHash") == evidence.get("policyBundleHash")
    )
    if retained and isinstance(bundle, dict):
        bundle = cast(dict[str, object], bundle)
        identity.update(
            {
                "bundle_hash": bundle.get("bundleHash"),
                "contract_version": bundle.get("contractVersion"),
                "workspace_id": bundle.get("workspaceId"),
                "revision": bundle.get("revision") or bundle.get("policyRevision"),
            }
        )
    if isinstance(last_error, dict):
        last_error = cast(dict[str, object], last_error)
        identity["last_error"] = {
            "reason": _public_error_code(last_error.get("reason")),
            "retained_last_good": retained,
        }
    return identity


def _public_sync_summary(summary: object) -> dict[str, object]:
    if not isinstance(summary, dict):
        return {}
    summary = cast(dict[str, object], summary)
    return {
        "synced_at": summary.get("synced_at"),
        "remote_policies_stored": summary.get("remote_policies_stored"),
        "receipts_stored": summary.get("receipts_stored"),
        "pain_signals_uploaded": summary.get("pain_signals_uploaded"),
        "pain_signals_status": summary.get("pain_signals_upload_status"),
        "telemetry_degradation": (
            {"reason": "telemetry_degradation"}
            if summary.get("telemetry_status") == "degraded" or summary.get("telemetry_degradation") is not None
            else None
        ),
        "remote_policy_sync_blocked": summary.get("remote_policy_sync_blocked"),
    }


def _public_diagnostics(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        return {}
    value = cast(dict[str, object], value)
    oauth = _mapping(value.get("oauth"))
    worker = _mapping(value.get("worker"))
    outbox = _mapping(value.get("outbox"))
    capability = _mapping(value.get("capability"))
    return {
        "capability": {"valid": capability.get("valid"), "reason": _public_error_code(capability.get("reason"))},
        "oauth": {"configured": oauth.get("configured"), "state": oauth.get("state")},
        "outbox": {"depth": outbox.get("depth"), "state": outbox.get("state")},
        "worker": {
            "state": worker.get("state"),
            "exact_review_route_error": (
                "exact_review_route_unavailable" if worker.get("exact_review_route_error") is not None else None
            ),
        },
    }


def _mapping(value: object) -> dict[str, object]:
    return cast(dict[str, object], value) if isinstance(value, dict) else {}


def _public_error_code(value: object) -> str | None:
    if value is None:
        return None
    if isinstance(value, str) and (
        any(entry["code"] == value for entry in policy_runtime_error_catalog())
        or policy_bundle_rejection_message(value) is not None
    ):
        return value
    return "unclassified_failure"
