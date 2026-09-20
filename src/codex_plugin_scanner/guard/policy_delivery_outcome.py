"""Bounded Cloud delivery diagnostics, separate from verified local authority."""

from __future__ import annotations

from collections.abc import Mapping

_FIELDS = (
    "policy_delivery_status",
    "policy_delivery_reason",
    "policy_delivery_remediation",
)
_REASONS = frozenset(
    {
        "extension_bundle_incompatible",
        "managed_controls_rollout_required",
        "managed_controls_publication_unavailable",
        "managed_controls_delivery_disabled",
        "policy_download_failed",
    }
)
_REMEDIATION = (
    "Cloud did not deliver a new policy. Review the Cloud policy delivery requirements, "
    "then sync again after resolving them. Check policy application status for current protection."
)


def policy_delivery_outcome_fields(value: object) -> dict[str, object]:
    """Never trust server prose, identifiers, diagnostics, or an application claim."""
    if not isinstance(value, Mapping):
        return {}
    status = value.get("status")
    if not isinstance(status, str) or status not in {"unavailable", "invalid"}:
        return {}
    code = value.get("code")
    reason = code if isinstance(code, str) and len(code) <= 96 and code in _REASONS else "policy_download_failed"
    return {
        "policy_delivery_status": status,
        "policy_delivery_reason": reason,
        "policy_delivery_remediation": _REMEDIATION,
    }


def policy_delivery_summary_fields(summary: Mapping[str, object]) -> dict[str, object]:
    """Reconstruct display guidance, even when reading persisted summary fields."""
    return policy_delivery_outcome_fields(
        {
            "status": summary.get("policy_delivery_status"),
            "code": summary.get("policy_delivery_reason"),
        }
    )


def sanitize_policy_delivery_summary(payload: dict[str, object], source: Mapping[str, object]) -> None:
    fields = policy_delivery_summary_fields(source)
    for key in _FIELDS:
        payload.pop(key, None)
    payload.update(fields)
