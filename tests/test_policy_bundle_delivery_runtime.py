from __future__ import annotations

import copy
import json
import threading
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.managed_controls_policy_bundle import (
    signed_cloud_extension_projection_digest,
    signed_cloud_extension_projection_json,
)
from codex_plugin_scanner.guard.policy_bundle_delivery import (
    effective_projection_digest,
    policy_bundle_acknowledgement_payload,
)
from codex_plugin_scanner.guard.policy_bundle_parser import policy_bundle_acceptance_checkpoint
from codex_plugin_scanner.guard.runtime import runner
from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.runtime.extension_catalog_sync import (
    MANAGED_CONTROLS_RUNTIME_CAPABILITIES,
)
from codex_plugin_scanner.guard.runtime.extension_control_runtime import ExtensionControlRuntime
from codex_plugin_scanner.guard.store import GuardStore
from tests.managed_controls_activation_support import CAPABILITIES, parse_managed_bundle
from tests.support.network import stub_authenticated_urlopen
from tests.test_guard_runtime import _seed_guard_cloud

_VECTOR_PATH = (
    Path(__file__).resolve().parents[1]
    / "contracts/managed-controls/v1/policy-bundle-v2-extension-signature-vector.json"
)
_GUARD_RELEASE_CATALOG_DIGEST = "e60c5b126c877ad76731670be05dffb5671ac33f3b237749c1882547e149dd6c"
_GUARD_RELEASE_PROJECTION_DIGEST = "sha256:fbf3242728658d0e3411112de98d9c9023d133adf506f78be999de3e4ffbd50f"


class _Response:
    def __init__(self, payload: dict[str, object]) -> None:
        self._payload = payload

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def read(self) -> bytes:
        return json.dumps(self._payload).encode("utf-8")


def _enable_delivery(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in (
        "GUARD_EXTENSION_CATALOG_SYNC_V1",
        "GUARD_POLICY_EXTENSION_TARGETS_V1",
        "GUARD_MANAGED_EXTENSION_CONTROLS_V1",
        "GUARD_MANAGED_CONTROLS_ATOMIC_APPLY_V1",
    ):
        monkeypatch.setenv(name, "true")


def _bundle() -> dict[str, object]:
    value = json.loads(_VECTOR_PATH.read_text())["bundle"]
    assert isinstance(value, dict)
    return value


def test_signed_cloud_extension_projection_matches_shared_vector() -> None:
    vector_path = _VECTOR_PATH.with_name("extension-projection-digest-vector.json")
    vector = json.loads(vector_path.read_text())

    assert vector["catalogDigest"] == _GUARD_RELEASE_CATALOG_DIGEST
    assert vector["expectedExtensionProjectionDigest"] == _GUARD_RELEASE_PROJECTION_DIGEST
    assert (
        vector["catalogDigest"]
        == runner.build_builtin_extension_catalog_wire(
            guard_version="test",
            generated_at="2026-08-25T12:00:00Z",
        )["catalogDigest"]
    )
    assert (
        signed_cloud_extension_projection_json(
            parse_managed_bundle(_bundle()),
            catalog_digest=vector["catalogDigest"],
        )
        == vector["canonicalProjectionJson"]
    )
    assert (
        signed_cloud_extension_projection_digest(
            parse_managed_bundle(_bundle()),
            catalog_digest=vector["catalogDigest"],
        )
        == _GUARD_RELEASE_PROJECTION_DIGEST
    )


def _stub_sync(monkeypatch: pytest.MonkeyPatch, response: dict[str, object]) -> None:
    stub_authenticated_urlopen(monkeypatch, lambda request, timeout: _Response(response))
    monkeypatch.setattr(
        runner,
        "validate_synced_policy_bundle",
        lambda policy_bundle, *args, **kwargs: (policy_bundle, None, ()),
    )
    monkeypatch.setattr(
        runner,
        "cached_policy_bundle_validation",
        lambda _store, policy_bundle: (
            (policy_bundle, None) if isinstance(policy_bundle, dict) else (None, "invalid_policy_bundle")
        ),
    )
    monkeypatch.setattr(runner, "sync_pain_signals", lambda _store, auth_context=None: 0)


def _v2_delivery(*, bundle_version: int = 7, bundle_hash: str = "sha256:" + "a" * 64):
    return {
        "workspaceId": "workspace-a",
        "deviceId": "device-a",
        "deliveryId": "00000000-0000-4000-8000-000000000001",
        "runtimeSessionId": "runtime-a",
        "bundleId": "bundle-a",
        "bundleVersion": bundle_version,
        "bundleHash": bundle_hash,
        "policyRevision": bundle_version,
        "extensionAuthorityRevision": bundle_version,
        "catalogDigest": "b" * 64,
        "effectiveProjectionDigest": "sha256:" + "c" * 64,
        "payloadHash": "sha256:" + "d" * 64,
        "extensionProjectionDigest": "sha256:" + "e" * 64,
        "lastKnownGoodBundleHash": None,
    }


def test_receipt_sync_context_uploads_v2_policy_bundle_acknowledgement(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    acknowledgement = {
        "contractVersion": "guard-policy-bundle.v2",
        **_v2_delivery(bundle_version=3),
        "sequence": 1,
        "status": "applied",
        "observedAt": "2026-04-19T00:00:11Z",
        "appliedExtensionAuthorityRevision": 8,
        "appliedEffectiveProjectionDigest": "sha256:" + "f" * 64,
    }
    store.set_sync_payload("policy_bundle_ack", acknowledgement, "2026-04-19T00:00:11+00:00")

    context = runner._receipt_sync_context(
        store,
        local_guard_online_at="2026-04-19T00:01:00+00:00",
    )

    assert context["policyBundleAcknowledgementV2"] == acknowledgement
    assert "policyBundleAcknowledgement" not in context


def test_policy_bundle_v2_acknowledgement_sequence_is_monotonic_per_bundle() -> None:
    bundle = {
        "contractVersion": "guard-policy-bundle.v2",
        "workspaceId": "workspace-a",
        "bundleVersion": 7,
        "bundleHash": "sha256:" + "a" * 64,
    }
    first = policy_bundle_acknowledgement_payload(
        device_id="device-a",
        device_name="Guard",
        policy_bundle=bundle,
        synced_at="2026-06-05T13:30:00",
        delivery=_v2_delivery(),
        applied_extension_authority_revision=8,
        applied_effective_projection_digest="sha256:" + "f" * 64,
    )
    second = policy_bundle_acknowledgement_payload(
        device_id="device-a",
        device_name="Guard",
        policy_bundle=bundle,
        synced_at="2026-06-05T14:31:00+01:00",
        previous=first,
        delivery=_v2_delivery(),
        applied_extension_authority_revision=8,
        applied_effective_projection_digest="sha256:" + "f" * 64,
    )
    third = policy_bundle_acknowledgement_payload(
        device_id="device-a",
        device_name="Guard",
        policy_bundle=bundle,
        synced_at="2026-06-05T13:32:00Z",
        previous=second,
        delivery=_v2_delivery(),
        applied_extension_authority_revision=8,
        applied_effective_projection_digest="sha256:" + "f" * 64,
    )

    assert first == {
        "contractVersion": "guard-policy-bundle.v2",
        **_v2_delivery(),
        "appliedExtensionAuthorityRevision": 8,
        "appliedEffectiveProjectionDigest": "sha256:" + "f" * 64,
        "sequence": 1,
        "status": "applied",
        "observedAt": "2026-06-05T13:30:00Z",
        "errorCode": None,
    }
    assert second["sequence"] == 2
    assert second["observedAt"] == "2026-06-05T13:31:00Z"
    assert third["sequence"] == 3
    assert third["observedAt"] == "2026-06-05T13:32:00Z"


def test_policy_bundle_v2_acknowledgement_distinguishes_shadow_validation() -> None:
    bundle = {
        "contractVersion": "guard-policy-bundle.v2",
        "workspaceId": "workspace-a",
        "bundleVersion": 7,
        "bundleHash": "sha256:" + "a" * 64,
    }
    validated = policy_bundle_acknowledgement_payload(
        device_id="device-a",
        device_name="Guard",
        policy_bundle=bundle,
        synced_at="2026-06-05T13:30:00+00:00",
        status="validated",
        delivery=_v2_delivery(),
        applied_extension_authority_revision=8,
        applied_effective_projection_digest="sha256:" + "f" * 64,
    )
    applied = policy_bundle_acknowledgement_payload(
        device_id="device-a",
        device_name="Guard",
        policy_bundle=bundle,
        synced_at="2026-06-05T13:31:00+00:00",
        status="applied",
        previous=validated,
        delivery=_v2_delivery(),
        applied_extension_authority_revision=8,
        applied_effective_projection_digest="sha256:" + "f" * 64,
    )

    assert validated["status"] == "validated"
    assert applied["status"] == "applied"
    assert applied["sequence"] == 2


def test_policy_bundle_v2_acknowledgement_resets_sequence_for_new_bundle() -> None:
    previous = {
        "contractVersion": "guard-policy-bundle.v2",
        **_v2_delivery(),
        "appliedExtensionAuthorityRevision": 8,
        "appliedEffectiveProjectionDigest": "sha256:" + "f" * 64,
        "sequence": 8,
        "status": "applied",
        "observedAt": "2026-06-05T13:30:00Z",
    }
    acknowledgement = policy_bundle_acknowledgement_payload(
        device_id="device-a",
        device_name="Guard",
        policy_bundle={
            "contractVersion": "guard-policy-bundle.v2",
            "workspaceId": "workspace-a",
            "bundleVersion": 8,
            "bundleHash": "sha256:" + "b" * 64,
        },
        synced_at="2026-06-05T13:31:00+00:00",
        previous=previous,
        delivery=_v2_delivery(bundle_version=8, bundle_hash="sha256:" + "b" * 64),
        applied_extension_authority_revision=9,
        applied_effective_projection_digest="sha256:" + "0" * 64,
    )

    assert acknowledgement["sequence"] == 1
    assert acknowledgement["bundleVersion"] == 8


def test_receipt_sync_atomically_accepts_managed_delivery_and_emits_exact_v2_ack(
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
    runtime = ExtensionControlRuntime(authority)
    wire_digest = runner.build_builtin_extension_catalog_wire(
        guard_version="test", generated_at="2026-08-25T12:00:00Z"
    )["catalogDigest"]
    _device_id, _device_name = runner._guard_device_metadata(store)
    trusted_cloud_device_id = "oauth-machine-managed-controls"
    store.set_sync_payload(
        "runtime_session_summary",
        {
            "runtime_session_id": "runtime-managed-controls",
            "runtime_device_id": trusted_cloud_device_id,
            "extensionCatalogDigest": wire_digest,
            "extensionAuthorityRevision": authority.revision,
            "effectiveProjectionDigest": f"sha256:{runtime.current().effective_digest}",
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
        "deviceId": trusted_cloud_device_id,
        "runtimeSessionId": "runtime-managed-controls",
        "deliveryId": "00000000-0000-4000-8000-000000000001",
        "policyRevision": 7,
        "extensionAuthorityRevision": authority.revision,
        "catalogDigest": wire_digest,
        "effectiveProjectionDigest": f"sha256:{runtime.current().effective_digest}",
        "payloadHash": bundle["payloadHash"],
        "extensionProjectionDigest": signed_cloud_extension_projection_digest(
            parse_managed_bundle(bundle),
            catalog_digest=wire_digest,
        ),
        "lastKnownGoodBundleHash": rollback["lastGoodBundleHash"],
    }
    _stub_sync(
        monkeypatch,
        {
            "syncedAt": "2026-08-25T12:00:01",
            "receiptsStored": 0,
            "policyBundle": bundle,
            "policyBundleDelivery": delivery,
            "managedControlsCapabilities": sorted(MANAGED_CONTROLS_RUNTIME_CAPABILITIES),
        },
    )

    runner.sync_receipts(store, managed_controls_publish=runtime.publish_after_commit)

    acknowledgement = store.get_sync_payload("policy_bundle_ack")
    assert store.get_sync_payload("policy_bundle") == bundle, store.get_sync_payload("policy_bundle_last_error")
    assert acknowledgement == {
        "contractVersion": "guard-policy-bundle.v2",
        **delivery,
        "appliedExtensionAuthorityRevision": 1,
        "appliedEffectiveProjectionDigest": f"sha256:{runtime.current().effective_digest}",
        "sequence": 1,
        "status": "applied",
        "observedAt": "2026-08-25T12:00:01Z",
        "errorCode": None,
    }
    context = runner._receipt_sync_context(store, local_guard_online_at="2026-08-25T12:00:02Z")
    assert context["policyBundleAcknowledgementV2"] == acknowledgement


def test_receipt_sync_rejects_managed_bundle_without_delivery_and_makes_no_ack(
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
    runtime = ExtensionControlRuntime(authority)
    wire_digest = runner.build_builtin_extension_catalog_wire(
        guard_version="test", generated_at="2026-08-25T12:00:00Z"
    )["catalogDigest"]
    device_id, _device_name = runner._guard_device_metadata(store)
    store.set_sync_payload(
        "runtime_session_summary",
        {
            "runtime_session_id": "runtime-managed-controls",
            "runtime_device_id": device_id,
            "extensionCatalogDigest": wire_digest,
            "extensionAuthorityRevision": authority.revision,
            "effectiveProjectionDigest": f"sha256:{runtime.current().effective_digest}",
        },
        "2026-08-25T12:00:00Z",
    )
    _stub_sync(
        monkeypatch,
        {
            "syncedAt": "2026-08-25T12:00:01Z",
            "receiptsStored": 0,
            "policyBundle": bundle,
            "managedControlsCapabilities": sorted(MANAGED_CONTROLS_RUNTIME_CAPABILITIES),
        },
    )

    runner.sync_receipts(store)

    assert store.get_sync_payload("policy_bundle") is None
    assert store.get_sync_payload("policy_bundle_ack") is None
    assert store.get_sync_payload("policy_bundle_last_error") == {"reason": "missing_policy_bundle_delivery"}


def test_atomic_activation_rejects_stale_delivery_after_concurrent_managed_commit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    registry = BUILT_IN_COMMAND_EXTENSION_REGISTRY
    store._bootstrap_extension_control_authority(registry.catalog_digest, key=None)
    base = store.read_extension_control_authority_for_registry(registry)
    runtime = ExtensionControlRuntime(base)
    device_id, _ = runner._guard_device_metadata(store)
    current_digest = effective_projection_digest(base)
    wire_digest = runner.build_builtin_extension_catalog_wire(
        guard_version="test",
        generated_at="2026-08-25T12:00:00Z",
    )["catalogDigest"]

    committed_bundle = _bundle()
    stale_bundle = copy.deepcopy(committed_bundle)
    stale_bundle["bundleVersion"] = 8
    stale_bundle["bundleHash"] = "sha256:" + "c" * 64

    def delivery(bundle: dict[str, object], delivery_id: str) -> dict[str, object]:
        rollback = bundle["rollback"]
        assert isinstance(rollback, dict)
        return {
            "bundleId": f"policy-{bundle['bundleVersion']}",
            "bundleHash": bundle["bundleHash"],
            "bundleVersion": bundle["bundleVersion"],
            "workspaceId": bundle["workspaceId"],
            "deviceId": device_id,
            "runtimeSessionId": "runtime-managed-controls",
            "deliveryId": delivery_id,
            "policyRevision": 7,
            "extensionAuthorityRevision": base.revision,
            "catalogDigest": wire_digest,
            "effectiveProjectionDigest": current_digest,
            "payloadHash": bundle["payloadHash"],
            "extensionProjectionDigest": signed_cloud_extension_projection_digest(
                parse_managed_bundle(bundle),
                catalog_digest=wire_digest,
            ),
            "lastKnownGoodBundleHash": rollback["lastGoodBundleHash"],
        }

    def activate(bundle: dict[str, object], delivery_payload: dict[str, object]):
        return store.apply_policy_bundle_authority(
            [],
            "2026-08-25T12:00:01Z",
            policy_bundle=bundle,
            policy_bundle_keyring={"keys": []},
            cloud_exceptions=[],
            policy_bundle_ack={},
            policy_bundle_checkpoint=policy_bundle_acceptance_checkpoint(bundle),
            update_last_good=True,
            managed_controls_policy=parse_managed_bundle(bundle),
            managed_controls_negotiated_capabilities=CAPABILITIES,
            managed_controls_delivery=delivery_payload,
            managed_controls_publish=runtime.publish_after_commit,
            remote_write_authorized=True,
        )

    stale_waiting = threading.Event()
    release_stale = threading.Event()
    original_prepare = store._prepared_remote_policy_rows

    def gated_prepare(*args, **kwargs):
        result = original_prepare(*args, **kwargs)
        if threading.current_thread().name == "stale-managed-delivery":
            stale_waiting.set()
            assert release_stale.wait(timeout=5)
        return result

    monkeypatch.setattr(store, "_prepared_remote_policy_rows", gated_prepare)
    stale_result: list[dict[str, object] | None] = []
    stale_thread = threading.Thread(
        target=lambda: stale_result.append(
            activate(
                stale_bundle,
                delivery(stale_bundle, "00000000-0000-4000-8000-000000000002"),
            )
        ),
        name="stale-managed-delivery",
    )
    stale_thread.start()
    assert stale_waiting.wait(timeout=5)

    committed = activate(
        committed_bundle,
        delivery(committed_bundle, "00000000-0000-4000-8000-000000000001"),
    )
    release_stale.set()
    stale_thread.join(timeout=5)

    assert committed is not None
    assert stale_result == [None]
    assert store.get_sync_payload("policy_bundle") == committed_bundle
    assert runtime.current().managed_revision == 1
