"""Cloud policy status fields and sync rows shared by CLI projections."""

from __future__ import annotations

from collections.abc import Mapping

from ..policy_bundle_parser import policy_bundle_rejection_message
from ..policy_delivery_outcome import policy_delivery_summary_fields


def policy_rejection_diagnostic(reason: object) -> dict[str, object] | None:
    """Explain only recognized bundle codes, never persisted message content."""
    if not isinstance(reason, str) or len(reason) > 96:
        return None
    remediation = policy_bundle_rejection_message(reason)
    if remediation is None:
        return None
    return {
        "code": reason,
        # A rejected signature authenticates no individual rule identifier.
        "rule_id": None,
        "field_path": "$.verifier"
        if reason in {"bundle_signature_invalid", "invalid_signature_encoding", "invalid_verifier"}
        else "$",
        "remediation": remediation,
    }


def _optional_string(value: object) -> str | None:
    return value if isinstance(value, str) and value else None


def cloud_policy_sync_fields(
    policy_bundle: Mapping[str, object],
    policy_bundle_last_error: Mapping[str, object],
    sync_summary: Mapping[str, object],
    cached_policy_bundle_error: str | None,
) -> dict[str, object]:
    reason = cached_policy_bundle_error or _optional_string(policy_bundle_last_error.get("reason"))
    return {
        "cloud_policy_bundle_hash": _optional_string(policy_bundle.get("bundleHash")),
        "cloud_policy_bundle_version": _optional_string(policy_bundle.get("bundleVersion")),
        "cloud_policy_rollout_state": _optional_string(policy_bundle.get("rolloutState")),
        "cloud_policy_sync_error": reason,
        "policy_rejection_diagnostic": policy_rejection_diagnostic(reason),
        "receipt_upload_status": _optional_string(sync_summary.get("receipt_upload_status")),
        "policy_validation_status": _optional_string(sync_summary.get("policy_validation_status")),
        "policy_application_status": _optional_string(sync_summary.get("policy_application_status")),
        "policy_rejection_reason": _optional_string(sync_summary.get("policy_rejection_reason")),
        **policy_delivery_summary_fields(sync_summary),
    }


def sync_output_rows(payload: Mapping[str, object]) -> list[tuple[str, str]]:
    rows: list[tuple[str, str]] = []
    rows.append(("Synced at", str(payload.get("synced_at") or "unknown")))
    rows.append(("Receipts sent", str(payload.get("receipts") or 0)))
    rows.append(("Inventory tracked", str(payload.get("inventory_tracked", payload.get("inventory")) or 0)))
    rows.append(("Receipts stored", str(payload.get("receipts_stored") or 0)))
    rows.append(("Advisories stored", str(payload.get("advisories_stored") or 0)))
    remote_policies_stored = payload.get("remote_policies_stored")
    exceptions_stored = payload.get("exceptions_stored")
    pain_signals_uploaded = payload.get("pain_signals_uploaded")
    if remote_policies_stored is not None:
        rows.append(("Remote policies", str(remote_policies_stored or 0)))
    if exceptions_stored is not None:
        rows.append(("Exceptions stored", str(exceptions_stored or 0)))
    if pain_signals_uploaded is not None:
        rows.append(("Pain signals uploaded", str(pain_signals_uploaded or 0)))
    if payload.get("receipt_upload_status") is not None:
        rows.append(("Receipt upload", str(payload.get("receipt_upload_status"))))
    if payload.get("policy_validation_status") is not None:
        rows.append(("Policy validation", str(payload.get("policy_validation_status"))))
    if payload.get("policy_application_status") is not None:
        rows.append(("Policy application", str(payload.get("policy_application_status"))))
    if payload.get("policy_rejection_reason"):
        rows.append(("Policy rejection", str(payload.get("policy_rejection_reason"))))
    diagnostic = policy_rejection_diagnostic(payload.get("policy_rejection_reason"))
    if diagnostic is not None:
        rows.append(("Next step", str(diagnostic["remediation"])))
    delivery = policy_delivery_summary_fields(payload)
    if delivery:
        rows.append(("Policy delivery", str(delivery["policy_delivery_status"])))
        rows.append(("Delivery next step", str(delivery["policy_delivery_remediation"])))
    return rows
