"""Generic v2 policy acknowledgements that are not extension-delivery proofs."""

from __future__ import annotations

from typing import Literal

from .policy_bundle_ack_contract import (
    GENERIC_ACK_IDENTITY,
    normalized_observed_at,
    validated_generic_policy_acknowledgement,
)
from .policy_bundle_v2 import POLICY_BUNDLE_V2_CONTRACT


def generic_policy_bundle_acknowledgement(
    *,
    device_id: str,
    policy_bundle: dict[str, object],
    synced_at: str,
    applied: bool,
    previous: dict[str, object] | None = None,
) -> dict[str, object]:
    """Bind a generic revision/device ack without fabricating extension proofs."""

    bundle_version = policy_bundle.get("bundleVersion")
    bundle_hash = policy_bundle.get("bundleHash")
    workspace_id = policy_bundle.get("workspaceId")
    identity = {
        "contractVersion": POLICY_BUNDLE_V2_CONTRACT,
        "workspaceId": workspace_id,
        "deviceId": device_id,
        "bundleVersion": bundle_version,
        "bundleHash": bundle_hash,
    }
    matching_previous = (
        previous
        if previous is not None
        and validated_generic_policy_acknowledgement(previous)[0] is not None
        and all(previous.get(key) == identity[key] for key in GENERIC_ACK_IDENTITY)
        else None
    )
    if matching_previous is not None and matching_previous.get("status") == "applied" and not applied:
        return dict(matching_previous)
    previous_sequence = matching_previous.get("sequence") if matching_previous is not None else None
    was_applied = matching_previous is not None and matching_previous.get("status") == "applied"
    status: Literal["received", "applied"] = "applied" if applied or was_applied else "received"
    acknowledgement = {
        "contractVersion": POLICY_BUNDLE_V2_CONTRACT,
        **identity,
        "sequence": previous_sequence + 1 if isinstance(previous_sequence, int) else 1,
        "status": status,
        "observedAt": normalized_observed_at(synced_at),
        "errorCode": None,
    }
    validated, _error = validated_generic_policy_acknowledgement(acknowledgement, previous=matching_previous)
    return validated if validated is not None else {}


def is_generic_policy_bundle_acknowledgement(acknowledgement: dict[str, object]) -> bool:
    return acknowledgement.get("contractVersion") == POLICY_BUNDLE_V2_CONTRACT and "deliveryId" not in acknowledgement


def validated_generic_policy_bundle_acknowledgement(
    acknowledgement: dict[str, object], *, previous: dict[str, object] | None = None
) -> tuple[dict[str, object] | None, str | None]:
    """Preserve the generic entry point while validating the existing Cloud wire schema."""
    if "deliveryId" in acknowledgement:
        return None, "generic_ack_managed_fields"
    validated, error = validated_generic_policy_acknowledgement(acknowledgement, previous=previous)
    if error == "acknowledgement_transition_rejected" and previous is not None and previous.get("status") == "applied":
        return None, "acknowledgement_regression"
    return validated, error
