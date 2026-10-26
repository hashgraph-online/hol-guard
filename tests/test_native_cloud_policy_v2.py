"""Compiled native proofs and atomic receipts using synthetic local adapters."""

from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.catalog_delivery import discovery
from codex_plugin_scanner.guard.managed_controls_policy_bundle import (
    parsed_managed_controls_from_validated_policy_bundle,
)
from codex_plugin_scanner.guard.managed_controls_policy_fields import ManagedControlsPolicyError
from codex_plugin_scanner.guard.native_policy_snapshot_publisher import provision_native_verifier_key_for_store
from codex_plugin_scanner.guard.native_resident_client import close_native_residents
from codex_plugin_scanner.guard.policy_bundle_delivery import (
    effective_projection_digest,
    validated_managed_policy_delivery,
)
from codex_plugin_scanner.guard.policy_bundle_parser import policy_bundle_acceptance_checkpoint
from codex_plugin_scanner.guard.runtime import extension_catalog_completion as cloud
from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY as REGISTRY
from codex_plugin_scanner.guard.runtime.extension_catalog_pages import _raw_extension
from codex_plugin_scanner.guard.store import GuardStore
from tests.managed_controls_activation_support import CAPABILITIES, managed_bundle
from tests.native_cloud_helpers import native_bridge as native_bridge
from tests.native_cloud_helpers import prepare_native, synthetic_completion


@pytest.mark.parametrize("active_catalog_transition", [False, True])
def test_native_v2_atomic_apply_receipt_and_stale_rejection(
    tmp_path, monkeypatch, native_bridge, native_hook_force, active_catalog_transition
):
    home = (tmp_path / "guard-home").resolve()
    store = GuardStore(home)
    for flag in (
        "GUARD_EXTENSION_CATALOG_SYNC_V1",
        "GUARD_MANAGED_EXTENSION_CONTROLS_V1",
        "GUARD_POLICY_EXTENSION_TARGETS_V1",
        "GUARD_MANAGED_CONTROLS_ATOMIC_APPLY_V1",
    ):
        monkeypatch.setenv(flag, "true")
    store._bootstrap_extension_control_authority(REGISTRY.catalog_digest, key=None)
    provision_native_verifier_key_for_store(store)
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    view = prepare_native(
        home=home,
        generated_at=now,
        enforcement_digest=REGISTRY.catalog_digest,
        values=sorted([_raw_extension(item) for item in REGISTRY.extensions], key=lambda item: item["extension_id"]),
    )
    handle = SimpleNamespace(root=view.discovery_root, authority=view.discovery_authority)
    monkeypatch.setattr(discovery, "installed_discovery", lambda _home: handle)
    monkeypatch.setattr(discovery, "require_handle", lambda value, _home: value)
    bundle = managed_bundle()
    summary = {
        "runtime_session_id": "fixture-runtime",
        "runtime_credential_id": "fixture-runtime",
        "runtime_device_id": "fixture-device",
        "extensionCatalogDigest": "e" * 64,
        "extensionCatalogViewDigest": view.manifest["catalogDigest"],
        "extensionCatalogEnforcementDigest": REGISTRY.catalog_digest,
        "extensionCatalogGeneratedAt": now,
        "managedControlsCapabilities": [*CAPABILITIES, "extension-catalog.v2"],
        "policyMetadataObservedAt": now,
        "policyMetadataIdentity": {
            "ownerUserId": "fixture-owner",
            "workspaceId": bundle["workspaceId"],
            "deviceId": "fixture-device",
            "runtimeId": "fixture-runtime",
        },
    }
    # Synthetic transport is explicit here; actual HTTP is qualified separately.
    summary["policyMetadataObservedAt"] = synthetic_completion(
        view, summary["policyMetadataIdentity"], now, native_bridge
    )["observedAt"]
    store.set_sync_payload("runtime_session_summary", summary, now)
    try:
        parsed = parsed_managed_controls_from_validated_policy_bundle(
            bundle, registry=REGISTRY, negotiated_capabilities=CAPABILITIES, guard_home=home, runtime_summary=summary
        )
        assert parsed.cloud_projection_digest is not None
        assert parsed.signed_cloud_layer.catalog_digest == REGISTRY.catalog_digest
        base = store.read_extension_control_authority_for_registry(REGISTRY)
        summary.update(
            extensionAuthorityRevision=base.revision, effectiveProjectionDigest=effective_projection_digest(base)
        )
        store.set_sync_payload("runtime_session_summary", summary, now)
        delivery = {
            "bundleId": "fixture-bundle",
            "bundleHash": bundle["bundleHash"],
            "bundleVersion": bundle["bundleVersion"],
            "workspaceId": bundle["workspaceId"],
            "deviceId": "fixture-device",
            "runtimeSessionId": "fixture-runtime",
            "deliveryId": "12345678-1234-5234-8234-123456789abc",
            "policyRevision": 7,
            "extensionAuthorityRevision": base.revision,
            "catalogDigest": REGISTRY.catalog_digest,
            "effectiveProjectionDigest": effective_projection_digest(base),
            "payloadHash": bundle["payloadHash"],
            "extensionProjectionDigest": parsed.cloud_projection_digest,
            "lastKnownGoodBundleHash": bundle["rollback"]["lastGoodBundleHash"],
        }
        accepted, error = validated_managed_policy_delivery(
            policy_bundle=bundle,
            delivery_field_provided=True,
            delivery_payload=delivery,
            workspace_id=bundle["workspaceId"],
            device_id="fixture-device",
            runtime_summary=summary,
            expected_extension_projection_digest=parsed.cloud_projection_digest,
        )
        assert error is None and accepted == delivery

        def apply():
            return store.apply_policy_bundle_authority(
                [],
                now,
                policy_bundle=bundle,
                policy_bundle_keyring={"keys": []},
                cloud_exceptions=[],
                policy_bundle_ack={},
                policy_bundle_checkpoint=policy_bundle_acceptance_checkpoint(bundle),
                update_last_good=True,
                managed_controls_policy=parsed,
                managed_controls_negotiated_capabilities=CAPABILITIES,
                managed_controls_delivery=delivery,
                remote_write_authorized=True,
            )

        assert apply() is not None
        current_registry = REGISTRY
        if active_catalog_transition:
            # Authenticated active-pack capture adapter fixture only: this is
            # native policy/state/receipt rebind evidence, not pack installation
            # or matcher-admission qualification.
            from codex_plugin_scanner.guard.catalog_delivery import projection
            from codex_plugin_scanner.guard.native_command_control_binding import (
                NativeCommandProgramMetadata,
                load_native_command_program_metadata,
            )
            from codex_plugin_scanner.guard.runtime.extension_catalog_completion import current_catalog_registry
            from codex_plugin_scanner.guard.runtime.generated_command_catalog import GeneratedCommandCatalog

            metadata = load_native_command_program_metadata()
            current_registry = GeneratedCommandCatalog(REGISTRY.extensions, catalog_digest="f" * 64)
            active_metadata = NativeCommandProgramMetadata(
                metadata.program_digest, current_registry.catalog_digest, metadata.trust_digest
            )
            monkeypatch.setattr(projection, "capture", lambda _: (active_metadata, current_registry, None))
            assert current_catalog_registry(store).catalog_digest == current_registry.catalog_digest
            view = prepare_native(
                home=home,
                generated_at=now,
                enforcement_digest=current_registry.catalog_digest,
                values=sorted(
                    [_raw_extension(item) for item in REGISTRY.extensions], key=lambda item: item["extension_id"]
                ),
            )
            summary.update(
                extensionCatalogViewDigest=view.manifest["catalogDigest"],
                extensionCatalogEnforcementDigest=current_registry.catalog_digest,
                extensionCatalogGeneratedAt=view.manifest["generatedAt"],
            )
            summary["policyMetadataObservedAt"] = synthetic_completion(
                view, summary["policyMetadataIdentity"], now, native_bridge
            )["observedAt"]
            base = store.read_extension_control_authority_for_registry(current_registry)
            assert all(control.state.value == "disabled" for layer in base.layers for control in layer.controls)
            summary.update(
                extensionAuthorityRevision=base.revision, effectiveProjectionDigest=effective_projection_digest(base)
            )
            store.set_sync_payload("runtime_session_summary", summary, now)
            parsed = parsed_managed_controls_from_validated_policy_bundle(
                bundle,
                registry=current_registry,
                negotiated_capabilities=CAPABILITIES,
                guard_home=home,
                runtime_summary=summary,
            )
            delivery.update(
                catalogDigest=current_registry.catalog_digest,
                extensionAuthorityRevision=base.revision,
                effectiveProjectionDigest=effective_projection_digest(base),
                extensionProjectionDigest=parsed.cloud_projection_digest,
            )
            assert apply() is not None
        ack = store.get_sync_payload("policy_bundle_ack")
        assert ack["status"] == "applied" and ack["catalogDigest"] == current_registry.catalog_digest
        assert ack["extensionProjectionDigest"] == parsed.cloud_projection_digest
        assert cloud.policy_view_ready(store=store, registry=current_registry) is True
        from codex_plugin_scanner.guard.runtime.managed_controls_sync import managed_controls_runtime_sync_posture

        assert (
            "managed-controls-atomic-apply.v1"
            in managed_controls_runtime_sync_posture(store, generated_at=now)["managedControlsCapabilities"]
        )
        prior = store.get_sync_payload("managed_controls_active")
        summary["policyMetadataObservedAt"] = "2000-01-01T00:00:00Z"
        store.set_sync_payload("runtime_session_summary", summary, now)
        assert apply() is None
        assert store.get_sync_payload("managed_controls_active") == prior
        assert store.get_sync_payload("policy_bundle_ack") == ack
        assert cloud.policy_view_ready(store=store, registry=current_registry) is False
        with pytest.raises(ManagedControlsPolicyError, match="authenticated"):
            parsed_managed_controls_from_validated_policy_bundle(
                bundle,
                registry=current_registry,
                negotiated_capabilities=CAPABILITIES,
                guard_home=home,
                runtime_summary=summary,
            )
    finally:
        close_native_residents(home)


def test_readiness_requires_authenticated_completed_observation(tmp_path):
    store = SimpleNamespace(
        guard_home=tmp_path, get_sync_payload=lambda _key: {"managedControlsCapabilities": ["extension-catalog.v2"]}
    )
    assert cloud.policy_view_ready(store=store, registry=REGISTRY) is False
