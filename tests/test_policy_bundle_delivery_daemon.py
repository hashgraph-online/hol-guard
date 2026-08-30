"""Daemon regressions for runtime-bound Managed Controls delivery."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.daemon import GuardDaemonServer
from codex_plugin_scanner.guard.managed_controls_policy_bundle import (
    signed_cloud_extension_projection_digest,
)
from codex_plugin_scanner.guard.policy_bundle_trusted_keys import (
    policy_bundle_verification_key_from_public_key,
)
from codex_plugin_scanner.guard.runtime import runner
from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.runtime.extension_catalog_sync import (
    MANAGED_CONTROLS_RUNTIME_CAPABILITIES,
    build_builtin_extension_catalog_wire,
)
from codex_plugin_scanner.guard.runtime.extension_control_runtime import ExtensionControlRuntimeSnapshot
from codex_plugin_scanner.guard.store import GuardStore
from tests.managed_controls_activation_support import parse_managed_bundle
from tests.test_guard_headless_daemon_api import (
    _dashboard_token_for,
    _read_json_response,
    _request,
    _seed_guard_cloud,
)


def _fixture(store: GuardStore) -> tuple[dict[str, object], dict[str, object]]:
    path = (
        Path(__file__).resolve().parents[1]
        / "contracts/managed-controls/v1/policy-bundle-v2-extension-signature-vector.json"
    )
    bundle = copy.deepcopy(json.loads(path.read_text())["bundle"])
    assert isinstance(bundle, dict)
    verifier = bundle["verifier"]
    assert isinstance(verifier, dict)
    public_key_pem = verifier["publicKeyPem"]
    key_id = verifier["keyId"]
    assert isinstance(public_key_pem, str)
    assert isinstance(key_id, str)
    key = policy_bundle_verification_key_from_public_key(
        key_id=key_id,
        public_key_pem=public_key_pem,
        workspace_id="workspace-managed-controls",
    )
    store.set_sync_payload("policy_bundle_keyring", {"keys": [key.to_dict()]}, "2026-08-25T12:00:00Z")
    registry = BUILT_IN_COMMAND_EXTENSION_REGISTRY
    store._bootstrap_extension_control_authority(  # pyright: ignore[reportPrivateUsage]
        registry.catalog_digest,
        key=None,
    )
    authority = store.read_extension_control_authority_for_registry(registry)
    effective_digest = f"sha256:{ExtensionControlRuntimeSnapshot.from_authority_view(authority).effective_digest}"
    wire_digest = build_builtin_extension_catalog_wire(
        guard_version="test",
        generated_at="2026-08-25T12:00:00Z",
    )["catalogDigest"]
    device_id, _ = runner._guard_device_metadata(store)
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
    return bundle, {
        "bundleId": "policy-managed-controls",
        "bundleHash": bundle["bundleHash"],
        "bundleVersion": bundle["bundleVersion"],
        "workspaceId": bundle["workspaceId"],
        "deviceId": device_id,
        "runtimeSessionId": "runtime-managed-controls",
        "deliveryId": "00000000-0000-4000-8000-000000000001",
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


def _enable(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in (
        "GUARD_EXTENSION_CATALOG_SYNC_V1",
        "GUARD_POLICY_EXTENSION_TARGETS_V1",
        "GUARD_MANAGED_EXTENSION_CONTROLS_V1",
        "GUARD_MANAGED_CONTROLS_ATOMIC_APPLY_V1",
    ):
        monkeypatch.setenv(name, "true")


def _sync(
    store: GuardStore,
    *,
    bundle: dict[str, object],
    delivery: dict[str, object] | None,
) -> tuple[int, dict[str, object]]:
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    payload: dict[str, object] = {
        "harness": "codex",
        "operation": "policy_sync",
        "policy_bundle": json.dumps(bundle),
        "managedControlsCapabilities": sorted(MANAGED_CONTROLS_RUNTIME_CAPABILITIES),
    }
    if delivery is not None:
        payload["policyBundleDelivery"] = delivery
    try:
        return _read_json_response(
            _request(
                daemon.port,
                "/v1/policy/sync",
                token=_dashboard_token_for(store),
                payload=payload,
            )
        )
    finally:
        daemon.stop()


@pytest.mark.parametrize(
    ("mutation", "expected_error"),
    [("missing", "missing_policy_bundle_delivery"), ("runtime", "policy_bundle_delivery_mismatch")],
)
def test_daemon_rejects_extension_bundle_without_runtime_bound_delivery(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
    expected_error: str,
) -> None:
    _enable(monkeypatch)
    store = GuardStore(tmp_path / "guard-home")
    _seed_guard_cloud(store, workspace_id="workspace-managed-controls")
    bundle, delivery = _fixture(store)
    if mutation == "runtime":
        delivery["effectiveProjectionDigest"] = "sha256:" + "0" * 64
    status, response = _sync(
        store,
        bundle=bundle,
        delivery=None if mutation == "missing" else delivery,
    )

    assert status == 400
    assert response["error"] == expected_error
    assert store.get_sync_payload("policy_bundle") is None
    assert store.get_sync_payload("policy_bundle_ack") is None


def test_daemon_persists_only_post_commit_managed_ack(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _enable(monkeypatch)
    store = GuardStore(tmp_path / "guard-home")
    _seed_guard_cloud(store, workspace_id="workspace-managed-controls")
    bundle, delivery = _fixture(store)
    status, response = _sync(store, bundle=bundle, delivery=delivery)

    assert status == 200, response
    acknowledgement = store.get_sync_payload("policy_bundle_ack")
    assert isinstance(acknowledgement, dict)
    assert all(acknowledgement[key] == value for key, value in delivery.items())
    assert acknowledgement["appliedExtensionAuthorityRevision"] == 1
    snapshot = ExtensionControlRuntimeSnapshot.from_authority_view(
        store.read_extension_control_authority_for_registry(BUILT_IN_COMMAND_EXTENSION_REGISTRY)
    )
    assert acknowledgement["appliedEffectiveProjectionDigest"] == f"sha256:{snapshot.effective_digest}"


def test_daemon_accepts_cloud_normalized_device_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _enable(monkeypatch)
    store = GuardStore(tmp_path / "guard-home")
    _seed_guard_cloud(store, workspace_id="workspace-managed-controls")
    bundle, delivery = _fixture(store)
    trusted_device_id = "oauth-machine-managed-controls"
    delivery["deviceId"] = trusted_device_id
    runtime_summary = store.get_sync_payload("runtime_session_summary")
    assert isinstance(runtime_summary, dict)
    runtime_summary["runtime_device_id"] = trusted_device_id
    store.set_sync_payload(
        "runtime_session_summary",
        runtime_summary,
        "2026-08-25T12:00:00Z",
    )

    status, response = _sync(store, bundle=bundle, delivery=delivery)

    assert status == 200, response
    acknowledgement = store.get_sync_payload("policy_bundle_ack")
    assert isinstance(acknowledgement, dict)
    assert acknowledgement["deviceId"] == trusted_device_id
