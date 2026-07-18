"""Cross-repo Cloud exception sync proof (HGLP136-HGLP141)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.cloud_exceptions import (
    build_cloud_exceptions_from_policy_bundle,
    list_active_cloud_exceptions,
)
from codex_plugin_scanner.guard.policy_bundle_parser import validated_policy_bundle_payload
from codex_plugin_scanner.guard.runtime.runner import _persist_cloud_exceptions
from codex_plugin_scanner.guard.store import GuardStore
from tests.cloud_exception_bundle_fixtures import (
    build_cloud_exception_bundle_entry,
    build_cloud_exception_policy_bundle,
)
from tests.policy_bundle_signing_helpers import (
    policy_bundle_test_keyring,
    policy_bundle_test_verification_key,
)
from tests.test_policy_bundle_parser import computed_policy_bundle_hash


def _seed_guard_cloud(store, *, workspace_id=None, sync_url=None, token="demo-token", now="2026-05-19T00:00:00Z"):
    """Seed OAuth credentials (replaces legacy set_sync_credentials scaffolding).

    Also installs a test-only resolver override so sync-path exercises stay hermetic
    (no OAuth token refresh against the network). Tests that need real sync against a
    local server pass sync_url=<url>.
    """
    from codex_plugin_scanner.guard.cli.oauth_client import generate_dpop_key_pair
    from codex_plugin_scanner.guard.runtime import runner as guard_runner_module

    dpop_key_material = generate_dpop_key_pair()
    store.set_oauth_local_credentials(
        issuer="https://hol.org",
        client_id="guard-local-daemon",
        refresh_token=token,
        dpop_private_key_pem=dpop_key_material.private_key_pem,
        dpop_public_jwk=dpop_key_material.public_jwk,
        dpop_public_jwk_thumbprint=dpop_key_material.public_jwk_thumbprint,
        grant_id="grant-1",
        machine_id="machine-1",
        workspace_id=workspace_id,
        now=now,
    )
    effective_sync_url = sync_url if sync_url is not None else "https://hol.org/api/guard/receipts/sync"
    guard_runner_module._test_sync_auth_context_override = {
        "sync_url": effective_sync_url,
        "access_token": token,
        "dpop_key_material": None,
    }
    if workspace_id is not None:
        store.set_sync_payload(
            "policy_bundle_keyring",
            policy_bundle_test_keyring(workspace_id=workspace_id),
            now,
        )


class _JsonResponse:
    def __init__(self, payload: dict[str, object]) -> None:
        self._payload = payload

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def read(self) -> bytes:
        return json.dumps(self._payload).encode("utf-8")


def _cache_signed_policy_bundle_authority(
    store: GuardStore,
    *,
    policy_bundle: dict[str, object],
    now: str,
) -> tuple[str, dict[str, object]]:
    workspace_id = str(policy_bundle["workspaceId"])
    device_metadata = store.get_device_metadata()
    device_id = str(device_metadata["installation_id"])
    acknowledgement = {
        "appliedAt": now,
        "bundleHash": policy_bundle["bundleHash"],
        "bundleVersion": policy_bundle["bundleVersion"],
        "deviceId": device_id,
        "deviceName": str(device_metadata["device_label"]),
        "status": "synced",
    }
    store.set_sync_payload(
        "policy_bundle_keyring",
        policy_bundle_test_keyring(workspace_id=workspace_id),
        now,
    )
    store.set_sync_payload("policy_bundle", policy_bundle, now)
    store.set_sync_payload("policy_bundle_ack", acknowledgement, now)
    return device_id, acknowledgement


def test_hglp136_fixture_is_code_generated_not_static_ui_copy() -> None:
    bundle = build_cloud_exception_policy_bundle()
    assert isinstance(bundle.get("cloudExceptions"), list)
    assert bundle["cloudExceptions"][0]["exceptionId"] == "artifact:codex:sync-proof"


def test_hglp137_local_daemon_accepts_valid_exception_bundle(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "home")
    _seed_guard_cloud(store, workspace_id="workspace-sync-proof")
    device_id = str(store.get_device_metadata()["installation_id"])
    bundle = build_cloud_exception_policy_bundle(device_id=device_id)
    signing_key = policy_bundle_test_verification_key(workspace_id="workspace-sync-proof")
    validated, reason = validated_policy_bundle_payload(
        bundle,
        trusted_verification_keys=(signing_key,),
        anchored_verification_keys=(signing_key,),
        expected_workspace_id="workspace-sync-proof",
    )
    assert reason is None
    assert validated is not None
    cached_device_id, _acknowledgement = _cache_signed_policy_bundle_authority(
        store,
        policy_bundle=validated,
        now="2026-06-14T12:00:00+00:00",
    )
    serialized = _persist_cloud_exceptions(
        store,
        device_id=cached_device_id,
        policy_bundle=validated,
        now="2026-06-14T12:00:00+00:00",
    )
    assert [item["id"] for item in serialized] == ["artifact:codex:sync-proof"]
    listed = store.list_cloud_exceptions()
    assert len(listed) == 1
    assert listed[0]["id"] == "artifact:codex:sync-proof"
    assert listed[0]["provenance"] == "policy-bundle"
    assert listed[0]["ack_status"] == "synced"


def test_persist_cloud_exceptions_ignores_unsigned_sibling_and_requires_cached_bundle(
    tmp_path: Path,
) -> None:
    store = GuardStore(tmp_path / "home")
    _seed_guard_cloud(store, workspace_id="workspace-sync-proof")
    device_id = str(store.get_device_metadata()["installation_id"])
    bundle = build_cloud_exception_policy_bundle(device_id=device_id)
    signing_key = policy_bundle_test_verification_key(workspace_id="workspace-sync-proof")
    validated, reason = validated_policy_bundle_payload(
        bundle,
        trusted_verification_keys=(signing_key,),
        anchored_verification_keys=(signing_key,),
        expected_workspace_id="workspace-sync-proof",
    )
    assert reason is None
    assert validated is not None
    cached_device_id, _acknowledgement = _cache_signed_policy_bundle_authority(
        store,
        policy_bundle=validated,
        now="2026-06-14T12:00:00+00:00",
    )

    receipt_exception = build_cloud_exception_bundle_entry(
        exception_id="artifact:codex:receipt-sync",
    )
    serialized = _persist_cloud_exceptions(
        store,
        device_id=cached_device_id,
        sync_exceptions=[receipt_exception],
        policy_bundle=validated,
        now="2026-06-14T12:00:00+00:00",
    )
    assert {item["id"] for item in serialized} == {"artifact:codex:sync-proof"}
    assert {item["provenance"] for item in serialized} == {"policy-bundle"}
    assert {item["id"] for item in store.list_cloud_exceptions()} == {"artifact:codex:sync-proof"}

    store.delete_sync_payload("policy_bundle")
    _persist_cloud_exceptions(
        store,
        sync_exceptions=None,
        policy_bundle=None,
        now="2026-06-14T12:00:01+00:00",
    )

    assert store.get_sync_payload("cloud_exceptions") == []
    assert store.list_cloud_exceptions() == []


def test_hglp138_local_daemon_rejects_tampered_exception_bundle(tmp_path: Path) -> None:
    bundle = build_cloud_exception_policy_bundle()
    bundle["bundleHash"] = "sha256:tampered"
    signing_key = policy_bundle_test_verification_key(workspace_id="workspace-sync-proof")
    validated, reason = validated_policy_bundle_payload(
        bundle,
        trusted_verification_keys=(signing_key,),
        anchored_verification_keys=(signing_key,),
        expected_workspace_id="workspace-sync-proof",
    )
    assert validated is None
    assert reason == "bundle_hash_mismatch"


def test_hglp139_expired_cloud_exception_is_not_active_after_bundle_load() -> None:
    bundle = build_cloud_exception_policy_bundle(
        cloud_exceptions=[
            build_cloud_exception_bundle_entry(
                exception_id="artifact:codex:expired",
                expires_at="2020-01-01T00:00:00+00:00",
            )
        ]
    )
    items = build_cloud_exceptions_from_policy_bundle(bundle, device_id="device-sync-proof")
    active = list_active_cloud_exceptions(items, now="2026-06-14T12:00:00+00:00")
    assert active == []


def test_hglp140_wrong_workspace_bundle_is_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from codex_plugin_scanner.guard.runtime import runner as guard_runner_module

    store = GuardStore(tmp_path / "guard-home")
    _seed_guard_cloud(store, workspace_id="workspace-a")
    bundle = build_cloud_exception_policy_bundle(workspace_id="workspace-b")
    bundle["bundleHash"] = computed_policy_bundle_hash(bundle)

    def _fake_urlopen(request, timeout):
        if request.full_url.endswith("/api/v1/guard/events"):
            return _JsonResponse({"accepted": 0, "rejected": 0, "statuses": []})
        return _JsonResponse(
            {
                "syncedAt": "2026-06-14T12:00:01+00:00",
                "receiptsStored": 0,
                "policyBundle": bundle,
            }
        )

    monkeypatch.setattr(guard_runner_module.urllib.request, "urlopen", _fake_urlopen)
    monkeypatch.setattr(guard_runner_module, "sync_pain_signals", lambda _store, auth_context=None: 0)

    guard_runner_module.sync_receipts(store)

    assert store.get_sync_payload("policy_bundle") is None
    last_error = store.get_sync_payload("policy_bundle_last_error")
    assert isinstance(last_error, dict)
    assert last_error["reason"] == "wrong_workspace"
    assert "Reconnect Guard" in str(last_error["message"])


def test_hglp141_bundle_ack_metadata_is_available_for_sync_upload(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from codex_plugin_scanner.guard.runtime import runner as guard_runner_module

    store = GuardStore(tmp_path / "guard-home")
    _seed_guard_cloud(store, workspace_id="workspace-sync-proof")
    bundle = build_cloud_exception_policy_bundle()
    bundle["bundleHash"] = computed_policy_bundle_hash(bundle)
    requests: list[dict[str, object]] = []

    def _fake_urlopen(request, timeout):
        if request.full_url.endswith("/api/v1/guard/events"):
            return _JsonResponse({"accepted": 0, "rejected": 0, "statuses": []})
        body = json.loads(request.data.decode("utf-8"))
        requests.append(body)
        return _JsonResponse(
            {
                "syncedAt": f"2026-06-14T12:00:0{len(requests)}+00:00",
                "receiptsStored": 0,
                "policyBundle": bundle,
            }
        )

    monkeypatch.setattr(guard_runner_module.urllib.request, "urlopen", _fake_urlopen)
    monkeypatch.setattr(guard_runner_module, "sync_pain_signals", lambda _store, auth_context=None: 0)

    guard_runner_module.sync_receipts(store)
    guard_runner_module.sync_receipts(store)

    assert store.get_sync_payload("policy_bundle") is not None
    assert "policyBundleAcknowledgement" in requests[1]["syncContext"]
