from __future__ import annotations

import copy
import json
from pathlib import Path

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
