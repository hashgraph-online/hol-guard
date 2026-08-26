from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.policy_bundle_delivery import validate_policy_bundle_delivery
from codex_plugin_scanner.guard.policy_bundle_v2 import validated_policy_bundle_v2_acknowledgement
from codex_plugin_scanner.guard.runtime.extension_catalog_sync import build_builtin_extension_catalog_wire

_ROOT = Path(__file__).resolve().parents[1]
_VECTOR = json.loads(
    (_ROOT / "contracts/managed-controls/v1/policy-bundle-v2-extension-signature-vector.json").read_text()
)
_WIRE_CATALOG_DIGEST = build_builtin_extension_catalog_wire(
    guard_version="test",
    generated_at="2026-08-25T00:00:00Z",
)["catalogDigest"]


def _bundle() -> dict[str, object]:
    return copy.deepcopy(_VECTOR["bundle"])


def _runtime_summary() -> dict[str, object]:
    return {
        "runtime_session_id": "runtime-managed-controls",
        "runtime_device_id": "device-managed-controls",
        "extensionCatalogDigest": _WIRE_CATALOG_DIGEST,
        "extensionAuthorityRevision": 7,
        "effectiveProjectionDigest": "sha256:" + "c" * 64,
    }


def _delivery() -> dict[str, object]:
    bundle = _bundle()
    rollback = bundle["rollback"]
    assert isinstance(rollback, dict)
    return {
        "bundleId": "policy-managed-controls",
        "bundleHash": bundle["bundleHash"],
        "bundleVersion": bundle["bundleVersion"],
        "workspaceId": bundle["workspaceId"],
        "deviceId": "device-managed-controls",
        "runtimeSessionId": "runtime-managed-controls",
        "deliveryId": "00000000-0000-4000-8000-000000000001",
        "policyRevision": 7,
        "extensionAuthorityRevision": 7,
        "catalogDigest": _WIRE_CATALOG_DIGEST,
        "effectiveProjectionDigest": "sha256:" + "c" * 64,
        "payloadHash": bundle["payloadHash"],
        "extensionProjectionDigest": "sha256:" + "d" * 64,
        "lastKnownGoodBundleHash": rollback["lastGoodBundleHash"],
    }


def _validate(delivery: object):
    return validate_policy_bundle_delivery(
        delivery,
        policy_bundle=_bundle(),
        workspace_id="workspace-managed-controls",
        device_id="device-managed-controls",
        runtime_summary=_runtime_summary(),
    )


def test_delivery_binds_exact_cloud_correlation_to_signed_bundle_and_runtime_posture() -> None:
    delivery = _delivery()

    assert _validate(delivery) == (delivery, None)


@pytest.mark.parametrize(
    ("mutation", "reason"),
    [
        (lambda delivery: delivery.pop("deliveryId"), "invalid_policy_bundle_delivery_fields"),
        (lambda delivery: delivery.update({"attacker": "override"}), "invalid_policy_bundle_delivery_fields"),
        (lambda delivery: delivery.update({"bundleHash": "sha256:" + "0" * 64}), "policy_bundle_delivery_mismatch"),
        (lambda delivery: delivery.update({"workspaceId": "workspace-other"}), "policy_bundle_delivery_mismatch"),
        (lambda delivery: delivery.update({"deviceId": "device-other"}), "policy_bundle_delivery_mismatch"),
        (lambda delivery: delivery.update({"runtimeSessionId": "runtime-other"}), "policy_bundle_delivery_mismatch"),
        (lambda delivery: delivery.update({"catalogDigest": "0" * 64}), "policy_bundle_delivery_mismatch"),
        (lambda delivery: delivery.update({"policyRevision": 8}), "policy_bundle_delivery_mismatch"),
        (
            lambda delivery: delivery.update({"extensionAuthorityRevision": 8}),
            "policy_bundle_delivery_mismatch",
        ),
        (
            lambda delivery: delivery.update({"effectiveProjectionDigest": "sha256:" + "0" * 64}),
            "policy_bundle_delivery_mismatch",
        ),
        (lambda delivery: delivery.update({"payloadHash": "sha256:" + "0" * 64}), "policy_bundle_delivery_mismatch"),
        (lambda delivery: delivery.update({"lastKnownGoodBundleHash": None}), "policy_bundle_delivery_mismatch"),
    ],
)
def test_delivery_rejects_missing_unknown_and_mismatched_evidence(mutation, reason: str) -> None:
    delivery = _delivery()
    mutation(delivery)

    assert _validate(delivery) == (None, reason)


def test_delivery_requires_the_current_runtime_posture() -> None:
    validated, reason = validate_policy_bundle_delivery(
        _delivery(),
        policy_bundle=_bundle(),
        workspace_id="workspace-managed-controls",
        device_id="device-managed-controls",
        runtime_summary=None,
    )

    assert validated is None
    assert reason == "policy_bundle_delivery_runtime_unavailable"


def test_acknowledgement_requires_complete_delivery_evidence_and_rejects_unknown_fields() -> None:
    acknowledgement = {
        "contractVersion": "guard-policy-bundle.v2",
        **_delivery(),
        "appliedExtensionAuthorityRevision": 8,
        "appliedEffectiveProjectionDigest": "sha256:" + "e" * 64,
        "sequence": 1,
        "status": "applied",
        "observedAt": "2026-08-25T12:00:00Z",
    }
    assert validated_policy_bundle_v2_acknowledgement(acknowledgement) == (acknowledgement, None)

    missing = dict(acknowledgement)
    missing.pop("deliveryId")
    assert validated_policy_bundle_v2_acknowledgement(missing) == (None, "missing_required_field")
    unknown = {**acknowledgement, "x-attacker": "override"}
    assert validated_policy_bundle_v2_acknowledgement(unknown) == (None, "unknown_field")
