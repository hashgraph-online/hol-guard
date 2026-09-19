"""Existing policy ACK admission for receipt-upload context."""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING

from ..policy_bundle_ack_contract import generic_ack_matches_bundle
from ..policy_bundle_parser import non_empty_string
from ..policy_bundle_v2 import POLICY_BUNDLE_V2_CONTRACT, validated_policy_bundle_v2_acknowledgement
from ..synced_policy import validated_synced_policy_bundle

if TYPE_CHECKING:
    from ..store import GuardStore


def validated_upload_policy_acknowledgement(
    store: GuardStore,
    *,
    device_id: str,
    device_name: str,
    normalize_timestamp: Callable[[object], str | None],
) -> dict[str, object] | None:
    acknowledgement = store.get_sync_payload("policy_bundle_ack")
    if not isinstance(acknowledgement, dict):
        return None
    if acknowledgement.get("contractVersion") == POLICY_BUNDLE_V2_CONTRACT:
        validated, _error = validated_policy_bundle_v2_acknowledgement(acknowledgement)
        if (
            validated is not None
            and "deliveryId" not in validated
            and not generic_ack_matches_bundle(
                validated,
                validated_synced_policy_bundle(store),
                device_id=device_id,
            )
        ):
            return None
        return validated

    policy_bundle = validated_synced_policy_bundle(store)
    if policy_bundle is None:
        return None

    bundle_hash = non_empty_string(policy_bundle.get("bundleHash"))
    bundle_version = non_empty_string(policy_bundle.get("bundleVersion"))
    if bundle_hash is None or bundle_version is None:
        return None
    if acknowledgement.get("bundleHash") != bundle_hash:
        return None
    if acknowledgement.get("bundleVersion") != bundle_version:
        return None
    if acknowledgement.get("deviceId") != device_id:
        return None
    if acknowledgement.get("deviceName") != device_name:
        return None
    if acknowledgement.get("status") != "synced":
        return None
    if normalize_timestamp(acknowledgement.get("appliedAt")) is None:
        return None
    return acknowledgement
