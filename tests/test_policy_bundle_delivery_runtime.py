from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.policy_bundle_delivery import policy_bundle_acknowledgement_payload
from codex_plugin_scanner.guard.runtime import runner
from codex_plugin_scanner.guard.store import GuardStore
from tests.test_guard_runtime import _seed_guard_cloud

_VECTOR_PATH = (
    Path(__file__).resolve().parents[1]
    / "contracts/managed-controls/v1/policy-bundle-v2-extension-signature-vector.json"
)


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


def _stub_sync(monkeypatch: pytest.MonkeyPatch, response: dict[str, object]) -> None:
    monkeypatch.setattr(runner.urllib.request, "urlopen", lambda request, timeout: _Response(response))
    monkeypatch.setattr(
        runner,
        "validate_synced_policy_bundle",
        lambda policy_bundle, *args, **kwargs: (policy_bundle, None, ()),
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
    )
    second = policy_bundle_acknowledgement_payload(
        device_id="device-a",
        device_name="Guard",
        policy_bundle=bundle,
        synced_at="2026-06-05T14:31:00+01:00",
        previous=first,
        delivery=_v2_delivery(),
    )
    third = policy_bundle_acknowledgement_payload(
        device_id="device-a",
        device_name="Guard",
        policy_bundle=bundle,
        synced_at="2026-06-05T13:32:00Z",
        previous=second,
        delivery=_v2_delivery(),
    )

    assert first == {
        "contractVersion": "guard-policy-bundle.v2",
        **_v2_delivery(),
        "sequence": 1,
        "status": "applied",
        "observedAt": "2026-06-05T13:30:00Z",
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
    )
    applied = policy_bundle_acknowledgement_payload(
        device_id="device-a",
        device_name="Guard",
        policy_bundle=bundle,
        synced_at="2026-06-05T13:31:00+00:00",
        status="applied",
        previous=validated,
        delivery=_v2_delivery(),
    )

    assert validated["status"] == "validated"
    assert applied["status"] == "applied"
    assert applied["sequence"] == 2


def test_policy_bundle_v2_acknowledgement_resets_sequence_for_new_bundle() -> None:
    previous = {
        "contractVersion": "guard-policy-bundle.v2",
        **_v2_delivery(),
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
    registry = runner.BUILT_IN_COMMAND_EXTENSION_REGISTRY
    store._bootstrap_extension_control_authority(registry.catalog_digest, key=None)
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
            "extensionAuthorityRevision": 7,
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
        "deliveryId": "00000000-0000-4000-8000-000000000001",
        "policyRevision": 7,
        "extensionAuthorityRevision": 7,
        "catalogDigest": wire_digest,
        "effectiveProjectionDigest": bundle["payloadHash"],
        "lastKnownGoodBundleHash": rollback["lastGoodBundleHash"],
    }
    _stub_sync(
        monkeypatch,
        {
            "syncedAt": "2026-08-25T12:00:01",
            "receiptsStored": 0,
            "policyBundle": bundle,
            "policyBundleDelivery": delivery,
            "managedControlsCapabilities": sorted(runner.MANAGED_CONTROLS_RUNTIME_CAPABILITIES),
        },
    )

    runner.sync_receipts(store)

    acknowledgement = store.get_sync_payload("policy_bundle_ack")
    assert store.get_sync_payload("policy_bundle") == bundle
    assert acknowledgement == {
        "contractVersion": "guard-policy-bundle.v2",
        **delivery,
        "sequence": 1,
        "status": "applied",
        "observedAt": "2026-08-25T12:00:01Z",
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
    registry = runner.BUILT_IN_COMMAND_EXTENSION_REGISTRY
    store._bootstrap_extension_control_authority(registry.catalog_digest, key=None)
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
            "extensionAuthorityRevision": 7,
        },
        "2026-08-25T12:00:00Z",
    )
    _stub_sync(
        monkeypatch,
        {
            "syncedAt": "2026-08-25T12:00:01Z",
            "receiptsStored": 0,
            "policyBundle": bundle,
            "managedControlsCapabilities": sorted(runner.MANAGED_CONTROLS_RUNTIME_CAPABILITIES),
        },
    )

    runner.sync_receipts(store)

    assert store.get_sync_payload("policy_bundle") is None
    assert store.get_sync_payload("policy_bundle_ack") is None
    assert store.get_sync_payload("policy_bundle_last_error") == {"reason": "missing_policy_bundle_delivery"}
