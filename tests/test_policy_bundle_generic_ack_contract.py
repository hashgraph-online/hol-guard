"""Generic v2 acknowledgements match Cloud's existing non-managed contract."""

from __future__ import annotations

import pytest

from codex_plugin_scanner.guard.policy_bundle_delivery import policy_bundle_acknowledgement_payload
from codex_plugin_scanner.guard.policy_bundle_v2 import validated_policy_bundle_v2_acknowledgement
from tests.test_policy_bundle_generic_acknowledgement import _generic_v2_bundle

_GENERIC_KEYS = {
    "contractVersion",
    "workspaceId",
    "deviceId",
    "bundleVersion",
    "bundleHash",
    "sequence",
    "status",
    "observedAt",
    "errorCode",
}


def _ack(bundle: dict[str, object], *, applied: bool, previous=None) -> dict[str, object]:
    return policy_bundle_acknowledgement_payload(
        device_id="device-alpha",
        device_name="Guard",
        policy_bundle=bundle,
        synced_at="2026-07-15T12:02:00Z",
        status="applied" if applied else "validated",
        previous=previous,
    )


@pytest.mark.parametrize("applied", [False, True])
def test_generic_ack_has_no_managed_delivery_or_extension_proof(applied: bool) -> None:
    bundle = _generic_v2_bundle()
    ack = _ack(bundle, applied=applied)
    assert set(ack) == _GENERIC_KEYS
    assert ack["bundleHash"] == bundle["bundleHash"]
    assert ack["bundleVersion"] == bundle["bundleVersion"]
    assert ack["errorCode"] is None
    assert ack["status"] == ("applied" if applied else "received")
    assert validated_policy_bundle_v2_acknowledgement(ack) == (ack, None)


def test_matching_applied_ack_survives_later_unverified_observation() -> None:
    bundle = _generic_v2_bundle()
    applied = _ack(bundle, applied=True)
    refreshed = _ack(bundle, applied=False, previous=applied)
    assert refreshed["status"] == "applied"
    assert refreshed == applied
    assert refreshed["bundleHash"] == applied["bundleHash"]


def test_generic_validator_accepts_the_existing_cloud_schema() -> None:
    ack = {
        "contractVersion": "guard-policy-bundle.v2",
        "workspaceId": "workspace-1",
        "deviceId": "device-alpha",
        "bundleVersion": 7,
        "bundleHash": "sha256:" + "a" * 64,
        "sequence": 1,
        "status": "applied",
        "observedAt": "2026-07-15T12:02:00Z",
        "errorCode": None,
    }
    assert validated_policy_bundle_v2_acknowledgement(ack) == (ack, None)


@pytest.mark.parametrize(
    "field,value", [("sequence", True), ("bundleVersion", 2**53), ("workspaceId", ""), ("observedAt", "not-a-time")]
)
def test_generic_generator_rejects_invalid_bound_identity(field: str, value: object) -> None:
    bundle = _generic_v2_bundle()
    ack = _ack(bundle, applied=True)
    ack[field] = value
    validated, reason = validated_policy_bundle_v2_acknowledgement(ack)
    assert validated is None
    assert reason is not None
