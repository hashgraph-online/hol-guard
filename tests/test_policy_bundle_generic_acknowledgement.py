"""Generic generic-policy acknowledgements and empty-ack applied-status regressions."""

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric import rsa

from codex_plugin_scanner.guard.policy_bundle_delivery import (
    effective_policy_bundle_acknowledgement,
    policy_bundle_acknowledgement_payload,
)
from codex_plugin_scanner.guard.policy_bundle_generic_ack import (
    generic_policy_bundle_acknowledgement,
    is_generic_policy_bundle_acknowledgement,
    validated_generic_policy_bundle_acknowledgement,
)
from codex_plugin_scanner.guard.policy_bundle_v2 import POLICY_BUNDLE_V2_CONTRACT
from tests.test_policy_bundle_v2 import _signed_bundle, _verification_key

_MANAGED_PROOF_KEYS = (
    "deliveryId",
    "runtimeSessionId",
    "catalogDigest",
    "effectiveProjectionDigest",
    "extensionProjectionDigest",
    "extensionAuthorityRevision",
    "appliedExtensionAuthorityRevision",
    "appliedEffectiveProjectionDigest",
)


def _generic_v2_bundle() -> dict[str, object]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    verification_key = _verification_key(private_key)
    return _signed_bundle(private_key, verification_key)


def _assert_generic_lane(ack: dict[str, object]) -> None:
    assert is_generic_policy_bundle_acknowledgement(ack)
    assert "deliveryId" not in ack
    for key in _MANAGED_PROOF_KEYS:
        assert key not in ack


def test_generic_v2_ack_is_unverified_until_the_chosen_lane_applies() -> None:
    bundle = _generic_v2_bundle()
    unverified = policy_bundle_acknowledgement_payload(
        device_id="device-alpha",
        device_name="Guard",
        policy_bundle=bundle,
        synced_at="2026-07-15T12:01:00Z",
        status="validated",
    )
    applied = policy_bundle_acknowledgement_payload(
        device_id="device-alpha",
        device_name="Guard",
        policy_bundle=bundle,
        synced_at="2026-07-15T12:01:00Z",
        status="applied",
    )

    assert unverified["status"] == "received"
    assert unverified["errorCode"] is None
    assert unverified["status"] != "applied"
    assert applied["status"] == "applied"
    assert applied["deviceId"] == "device-alpha"
    assert "payloadHash" not in applied
    assert applied["bundleHash"] == bundle["bundleHash"]
    _assert_generic_lane(unverified)
    _assert_generic_lane(applied)


def test_empty_acknowledgement_never_counts_as_applied() -> None:
    empty = generic_policy_bundle_acknowledgement(
        device_id="device-alpha",
        policy_bundle={"contractVersion": POLICY_BUNDLE_V2_CONTRACT},
        synced_at="2026-07-15T12:01:00Z",
        applied=True,
    )
    assert empty == {}
    assert empty.get("status") != "applied"


def test_received_generic_ack_can_become_applied_after_the_lane_commits() -> None:
    bundle = _generic_v2_bundle()
    received = policy_bundle_acknowledgement_payload(
        device_id="device-alpha",
        device_name="Guard",
        policy_bundle=bundle,
        synced_at="2026-07-15T12:01:00Z",
        status="validated",
    )
    applied = policy_bundle_acknowledgement_payload(
        device_id="device-alpha",
        device_name="Guard",
        policy_bundle=bundle,
        synced_at="2026-07-15T12:02:00Z",
        status="applied",
        previous=received,
    )
    assert received["status"] == "received"
    assert applied["status"] == "applied"
    assert applied["sequence"] == received["sequence"] + 1
    assert applied["bundleHash"] == received["bundleHash"]
    _assert_generic_lane(applied)


def test_retained_generic_bundle_does_not_reuse_extension_delivery_as_proof() -> None:
    bundle = _generic_v2_bundle()
    ack = effective_policy_bundle_acknowledgement(
        device_id="device-alpha",
        device_name="Guard",
        effective_policy_bundle=bundle,
        validated_policy_bundle=bundle,
        validated_delivery=None,
        stored_acknowledgement=None,
        synced_at="2026-07-15T12:01:00Z",
        applied=False,
    )
    assert ack["status"] != "applied"
    assert "deliveryId" not in ack
    assert "extension-controls" not in str(ack.get("catalogDigest"))
    _assert_generic_lane(ack)


def test_applied_generic_ack_is_not_overwritten_when_rollout_later_disables() -> None:
    bundle = _generic_v2_bundle()
    applied = effective_policy_bundle_acknowledgement(
        device_id="device-alpha",
        device_name="Guard",
        effective_policy_bundle=bundle,
        validated_policy_bundle=bundle,
        validated_delivery=None,
        stored_acknowledgement=None,
        synced_at="2026-07-15T12:01:00Z",
        applied=True,
    )
    retained = effective_policy_bundle_acknowledgement(
        device_id="device-alpha",
        device_name="Guard",
        effective_policy_bundle=bundle,
        validated_policy_bundle=bundle,
        validated_delivery=None,
        stored_acknowledgement=applied,
        synced_at="2026-07-15T13:00:00Z",
        applied=False,
    )
    assert applied["status"] == "applied"
    assert retained == applied
    rejected, reason = validated_generic_policy_bundle_acknowledgement(
        {**applied, "status": "received", "sequence": applied["sequence"] + 1},
        previous=applied,
    )
    assert rejected is None
    assert reason == "acknowledgement_regression"


def test_generic_ack_validator_rejects_managed_delivery_fields() -> None:
    bundle = _generic_v2_bundle()
    ack = generic_policy_bundle_acknowledgement(
        device_id="device-alpha",
        policy_bundle=bundle,
        synced_at="2026-07-15T12:01:00Z",
        applied=True,
    )
    forged = dict(ack)
    forged["deliveryId"] = "00000000-0000-4000-8000-000000000001"
    validated, reason = validated_generic_policy_bundle_acknowledgement(forged)
    assert validated is None
    assert reason == "generic_ack_managed_fields"
