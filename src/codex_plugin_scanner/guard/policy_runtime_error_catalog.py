"""Source-linked runtime policy error catalog for UI and support export."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Final, TypedDict

from .policy_bundle_parser import policy_bundle_rejection_message


class PolicyRuntimeErrorEntry(TypedDict):
    code: str
    owner: str
    retryable: bool
    retained_authority: str
    next_action: str
    explanation: str
    source: str


_CATALOG: Final[tuple[PolicyRuntimeErrorEntry, ...]] = (
    {
        "code": "untrusted_signing_key",
        "owner": "workspace-admin",
        "retryable": True,
        "retained_authority": "last-known-good-policy",
        "next_action": "Provision or rotate the workspace policy signing key, then sync again.",
        "explanation": policy_bundle_rejection_message("untrusted_signing_key") or "",
        "source": "policy_bundle_parser.py",
    },
    {
        "code": "remote_exact_request_stale",
        "owner": "operator",
        "retryable": False,
        "retained_authority": "pending-request-unchanged",
        "next_action": (
            "Create a fresh Cloud Review request. The previous signed decision targeted a different binding."
        ),
        "explanation": "The signed Cloud decision no longer matches this request's action, claim, policy, or nonce.",
        "source": "exact_cloud_review_apply.py",
    },
    {
        "code": "remote_exact_wrong_target",
        "owner": "operator",
        "retryable": False,
        "retained_authority": "pending-request-unchanged",
        "next_action": "Review the request on the device and workspace that created it.",
        "explanation": "The signed decision was bound to a different workspace, machine, device, or grant.",
        "source": "exact_cloud_review_apply.py",
    },
    {
        "code": "remote_exact_replayed",
        "owner": "runtime",
        "retryable": False,
        "retained_authority": "original-application",
        "next_action": "No further local action is required. Cloud can retry result delivery only.",
        "explanation": "This receipt already consumed the exact request. Guard will not approve or resume it again.",
        "source": "store_exact_cloud_review.py",
    },
    {
        "code": "cloud_review_capability_revoked",
        "owner": "operator",
        "retryable": False,
        "retained_authority": "prior-applied-history",
        "next_action": "Enable Cloud Review again if personal consent is still intended, then create a new request.",
        "explanation": "Local Cloud Review consent was revoked or disabled before this leased decision could commit.",
        "source": "store_exact_cloud_review.py",
    },
    {
        "code": "remote_exact_step_up_required",
        "owner": "workspace-admin",
        "retryable": True,
        "retained_authority": "pending-request-unchanged",
        "next_action": "Complete a current workspace-admin step-up challenge, then re-review the request.",
        "explanation": (
            "Managed admin review requires a current MFA step-up. Personal Cloud Review consent is not enough."
        ),
        "source": "review_contracts.py",
    },
    {
        "code": "catalog-digest-mismatch",
        "owner": "device",
        "retryable": False,
        "retained_authority": "approved-restrictions",
        "next_action": (
            "Update HOL Guard on this device, or change the Cloud rule to a permission in the current catalog."
        ),
        "explanation": (
            "Managed policy named a catalog this runtime does not understand. It cannot be shown as applied."
        ),
        "source": "extension_control_resolver.py",
    },
    {
        "code": "unknown-permission-target",
        "owner": "workspace-admin",
        "retryable": False,
        "retained_authority": "approved-restrictions",
        "next_action": "Change the Cloud rule to a current catalog permission, or upgrade the device catalog.",
        "explanation": "The policy names a permission that is missing from this device's command catalog.",
        "source": "managed_controls_policy_fields_core.py",
    },
    {
        "code": "pending_request_requeue_failed",
        "owner": "operator",
        "retryable": True,
        "retained_authority": "existing-capability",
        "next_action": "Retry delivery without renewing consent. Renew only after credentials change.",
        "explanation": "Cloud Review consent is present, but pending request projection still needs a delivery retry.",
        "source": "cloud_review_settings.py",
    },
    {
        "code": "telemetry_degradation",
        "owner": "runtime",
        "retryable": True,
        "retained_authority": "applied-policy-and-ack",
        "next_action": "Policy already applied. Retry only the telemetry lane; do not treat the bundle as unapplied.",
        "explanation": "Pain-signal or event telemetry failed after policy application. Acknowledgement is retained.",
        "source": "runner.py",
    },
)


def policy_runtime_error_entry(code: str) -> PolicyRuntimeErrorEntry | None:
    for entry in _CATALOG:
        if entry["code"] == code:
            return entry.copy()
    return None


def explain_policy_runtime_error(code: str, *, detail: str | None = None) -> dict[str, object]:
    entry = policy_runtime_error_entry(code)
    if entry is None:
        return {
            "code": code,
            "owner": "operator",
            "retryable": False,
            "retained_authority": "unknown",
            "next_action": "Open policy support export and share the correlation identifiers with support.",
            "explanation": "Guard could not apply this policy change. The raw exception is not the only guidance.",
            "source": "policy_runtime_error_catalog.py",
            "detail": detail,
        }
    payload: dict[str, object] = dict(entry)
    if detail:
        payload["detail"] = detail
    return payload


def policy_runtime_error_catalog() -> tuple[Mapping[str, object], ...]:
    return tuple(dict(entry) for entry in _CATALOG)
