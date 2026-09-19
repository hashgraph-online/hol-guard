"""Project receipt upload separately from resident policy application evidence."""

from __future__ import annotations

from .policy_bundle_delivery import policy_bundle_has_extension_semantics
from .policy_bundle_v2 import POLICY_BUNDLE_V2_CONTRACT


def policy_sync_outcomes(
    *,
    candidate: dict[str, object] | None,
    resident: dict[str, object] | None,
    acknowledgement: object,
    committed: bool,
    provided: bool,
    canonical_enforcement: bool,
    rejection: dict[str, object],
) -> dict[str, object]:
    if candidate is not None:
        validation = "accepted"
    elif provided:
        validation = "rejected"
    else:
        validation = "omitted"
    new_resident = (
        committed
        and candidate is not None
        and resident is not None
        and candidate.get("bundleHash") == resident.get("bundleHash")
        and candidate.get("bundleVersion") == resident.get("bundleVersion")
    )
    application = "no_authority"
    if new_resident and resident is not None:
        if resident.get("contractVersion") != POLICY_BUNDLE_V2_CONTRACT or (
            isinstance(acknowledgement, dict)
            and acknowledgement.get("status") == "applied"
            and acknowledgement.get("bundleHash") == resident.get("bundleHash")
            and acknowledgement.get("bundleVersion") == resident.get("bundleVersion")
            and (canonical_enforcement or policy_bundle_has_extension_semantics(resident))
        ):
            application = "applied"
        else:
            application = "fallback" if not canonical_enforcement else "unverified"
    elif resident is not None:
        application = "retained"
    elif provided and not rejection:
        application = "rejected"
    reason = rejection.get("reason")
    if application == "fallback" and not reason:
        reason = "canonical_enforcement_disabled"
    return {
        "receipt_upload_status": "success",
        "policy_validation_status": validation,
        "policy_application_status": application,
        "policy_rejection_reason": reason,
    }
