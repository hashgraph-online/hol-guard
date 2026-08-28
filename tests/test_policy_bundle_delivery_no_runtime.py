from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.managed_controls_policy_bundle import (
    signed_cloud_extension_projection_digest,
)
from codex_plugin_scanner.guard.policy_bundle_activation import (
    PolicyBundleActivationRejectionError,
)
from codex_plugin_scanner.guard.policy_bundle_delivery import effective_projection_digest
from codex_plugin_scanner.guard.policy_bundle_parser import policy_bundle_acceptance_checkpoint
from codex_plugin_scanner.guard.runtime import runner
from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.runtime.extension_catalog_sync import (
    MANAGED_CONTROLS_RUNTIME_CAPABILITIES,
)
from codex_plugin_scanner.guard.store import GuardStore
from tests.managed_controls_activation_support import CAPABILITIES, parse_managed_bundle
from tests.test_guard_runtime import _seed_guard_cloud
from tests.test_policy_bundle_delivery_runtime import _bundle, _enable_delivery, _stub_sync


def test_receipt_sync_without_live_runtime_persists_delivery_and_typed_rejection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _enable_delivery(monkeypatch)
    bundle = _bundle()
    store = GuardStore(tmp_path / "guard-home")
    _seed_guard_cloud(store, workspace_id="workspace-managed-controls")
    registry = BUILT_IN_COMMAND_EXTENSION_REGISTRY
    store._bootstrap_extension_control_authority(registry.catalog_digest, key=None)
    authority = store.read_extension_control_authority_for_registry(registry)
    wire_digest = runner.build_builtin_extension_catalog_wire(
        guard_version="test", generated_at="2026-08-25T12:00:00Z"
    )["catalogDigest"]
    device_id, _device_name = runner._guard_device_metadata(store)
    effective_digest = effective_projection_digest(authority)
    store.set_sync_payload(
        "runtime_session_summary",
        {
            "runtime_session_id": "runtime-managed-controls",
            "runtime_device_id": device_id,
            "extensionCatalogDigest": wire_digest,
            "extensionAuthorityRevision": authority.revision,
            "effectiveProjectionDigest": effective_digest,
        },
        "2026-08-25T12:00:00Z",
    )
    rollback = bundle["rollback"]
    assert isinstance(rollback, dict)
    delivery = {
        "bundleId": "policy-managed-controls",
        "bundleHash": bundle["bundleHash"],
        "bundleVersion": bundle["bundleVersion"],
        "workspaceId": bundle["workspaceId"],
        "deviceId": device_id,
        "runtimeSessionId": "runtime-managed-controls",
        "deliveryId": "00000000-0000-4000-8000-000000000002",
        "policyRevision": 7,
        "extensionAuthorityRevision": authority.revision,
        "catalogDigest": wire_digest,
        "effectiveProjectionDigest": effective_digest,
        "payloadHash": bundle["payloadHash"],
        "extensionProjectionDigest": signed_cloud_extension_projection_digest(
            parse_managed_bundle(bundle),
            catalog_digest=wire_digest,
        ),
        "lastKnownGoodBundleHash": rollback["lastGoodBundleHash"],
    }
    with pytest.raises(PolicyBundleActivationRejectionError) as rejection:
        store.apply_policy_bundle_authority(
            [],
            "2026-08-25T12:00:00Z",
            policy_bundle=bundle,
            policy_bundle_keyring={"keys": []},
            cloud_exceptions=[],
            policy_bundle_ack={},
            policy_bundle_checkpoint=policy_bundle_acceptance_checkpoint(bundle),
            update_last_good=True,
            managed_controls_policy=parse_managed_bundle(bundle),
            managed_controls_negotiated_capabilities=CAPABILITIES,
            managed_controls_delivery={
                **delivery,
                "effectiveProjectionDigest": "sha256:" + "f" * 64,
            },
            raise_on_rejection=True,
            remote_write_authorized=True,
        )
    assert rejection.value.reason == "managed_controls_delivery_mismatch"

    _stub_sync(
        monkeypatch,
        {
            "syncedAt": "2026-08-25T12:00:01Z",
            "receiptsStored": 0,
            "policyBundle": bundle,
            "policyBundleDelivery": delivery,
            "managedControlsCapabilities": sorted(MANAGED_CONTROLS_RUNTIME_CAPABILITIES),
        },
    )
    runner.sync_receipts(store)

    acknowledgement = store.get_sync_payload("policy_bundle_ack")
    assert store.get_sync_payload("policy_bundle") == bundle, store.get_sync_payload("policy_bundle_last_error")
    assert isinstance(acknowledgement, dict)
    assert acknowledgement["deliveryId"] == delivery["deliveryId"]
    assert acknowledgement["status"] == "applied"
    assert acknowledgement["appliedExtensionAuthorityRevision"] == 1
    assert acknowledgement["appliedEffectiveProjectionDigest"] != effective_digest
    assert store.get_sync_payload("policy_bundle_last_error") == {}

    _stub_sync(
        monkeypatch,
        {
            "syncedAt": "2026-08-25T12:00:02Z",
            "receiptsStored": 0,
            "managedControlsCapabilities": sorted(MANAGED_CONTROLS_RUNTIME_CAPABILITIES),
        },
    )
    runner.sync_receipts(store)
    assert store.get_sync_payload("policy_bundle") == bundle, store.get_sync_payload("policy_bundle_last_error")
    assert store.get_sync_payload("policy_bundle_last_error") == {}

    def reject_activation(*_args: object, **_kwargs: object) -> None:
        raise PolicyBundleActivationRejectionError("managed_controls_delivery_mismatch")

    monkeypatch.setattr(store, "apply_policy_bundle_authority", reject_activation)
    runner.sync_receipts(store)
    assert store.get_sync_payload("policy_bundle_last_error") == {"reason": "managed_controls_delivery_mismatch"}
