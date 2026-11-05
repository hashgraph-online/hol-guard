"""A bundle that fails local validation is reported to Guard Cloud as failed.

Without this, Cloud kept the device's last applied acknowledgement and showed
the bundle as applied while Guard enforced nothing from it.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.policy_bundle_delivery import policy_bundle_acknowledgement_payload
from codex_plugin_scanner.guard.runtime import runner
from codex_plugin_scanner.guard.store import GuardStore
from tests.policy_bundle_signing_helpers import policy_bundle_test_keyring, sign_policy_bundle
from tests.support.network import stub_authenticated_urlopen
from tests.test_guard_runtime import _cache_signed_test_policy_bundle, _seed_guard_cloud

_SYNCED_AT = "2026-04-19T00:00:11+00:00"


def _synced_store(tmp_path: Path) -> tuple[GuardStore, dict[str, object], str, str]:
    store = GuardStore(tmp_path / "guard-home")
    _cache_signed_test_policy_bundle(store, [])
    policy_bundle = store.get_sync_payload("policy_bundle")
    assert isinstance(policy_bundle, dict)
    device_id, device_name = runner._guard_device_metadata(store)
    acknowledgement = policy_bundle_acknowledgement_payload(
        device_id=device_id,
        device_name=device_name,
        policy_bundle=policy_bundle,
        synced_at=_SYNCED_AT,
    )
    assert acknowledgement["status"] == "synced"
    store.set_sync_payload("policy_bundle_ack", acknowledgement, _SYNCED_AT)
    return store, policy_bundle, device_id, device_name


def test_cached_bundle_that_loses_its_workspace_is_reported_failed(tmp_path: Path) -> None:
    store, policy_bundle, device_id, device_name = _synced_store(tmp_path)
    # The stored OAuth binding loses its workspace, as when the token issuer
    # no longer matches: the cached bundle stops validating.
    store.set_sync_payload("oauth_local_credentials", {}, "2026-04-19T00:00:30+00:00")

    context = runner._receipt_sync_context(store, local_guard_online_at="2026-04-19T00:01:00+00:00")

    acknowledgement = context["policyBundleAcknowledgement"]
    assert isinstance(acknowledgement, dict)
    assert acknowledgement["status"] == "failed"
    assert acknowledgement["bundleHash"] == policy_bundle["bundleHash"]
    assert acknowledgement["bundleVersion"] == policy_bundle["bundleVersion"]
    assert acknowledgement["deviceId"] == device_id
    assert acknowledgement["deviceName"] == device_name
    assert store.get_sync_payload("policy_bundle_ack") == acknowledgement

    again = runner._receipt_sync_context(store, local_guard_online_at="2026-04-19T00:02:00+00:00")

    assert again["policyBundleAcknowledgement"] == acknowledgement


def test_valid_cached_bundle_keeps_its_synced_acknowledgement(tmp_path: Path) -> None:
    store, policy_bundle, _device_id, _device_name = _synced_store(tmp_path)

    context = runner._receipt_sync_context(store, local_guard_online_at="2026-04-19T00:01:00+00:00")

    assert context["policyBundleAcknowledgement"]["status"] == "synced"
    assert context["policyBundleAcknowledgement"]["bundleHash"] == policy_bundle["bundleHash"]


def test_clearing_authority_stores_the_failed_acknowledgement(tmp_path: Path) -> None:
    store, policy_bundle, device_id, _device_name = _synced_store(tmp_path)
    failed = {
        "appliedAt": "2026-04-19T00:05:00+00:00",
        "bundleHash": policy_bundle["bundleHash"],
        "bundleVersion": policy_bundle["bundleVersion"],
        "deviceId": device_id,
        "status": "failed",
    }

    store.clear_policy_bundle_authority(
        "2026-04-19T00:05:00+00:00",
        policy_bundle_last_error={"reason": "wrong_workspace"},
        policy_bundle_ack=failed,
    )

    assert store.get_sync_payload("policy_bundle") is None
    assert store.get_sync_payload("policy_bundle_ack") == failed


def test_rejected_delivered_bundle_is_reported_failed_in_the_same_cycle(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    _seed_guard_cloud(store, workspace_id="workspace-a")
    store.set_sync_payload(
        "policy_bundle_keyring",
        policy_bundle_test_keyring(workspace_id="workspace-a"),
        "2026-06-05T13:29:00Z",
    )
    bundle = sign_policy_bundle(
        {
            "contractVersion": "guard-policy-bundle.v1",
            "bundleVersion": "policy-2026-06-05.5",
            "bundleHash": "",
            "issuedAt": "2026-06-05T13:30:00+00:00",
            "expiresAt": None,
            "verifier": {
                "algorithm": "rsa-pss-sha256",
                "keyId": "guard-policy-bundle-v1",
                "signature": None,
            },
            "rolloutState": "enforcing",
            "workspaceId": "workspace-b",
            "policyDefaults": {
                "mode": "enforce",
                "defaultAction": "warn",
                "unknownPublisherAction": "review",
                "changedHashAction": "require-reapproval",
                "newNetworkDomainAction": "warn",
                "subprocessAction": "block",
                "telemetryEnabled": False,
                "syncEnabled": True,
            },
            "rules": [],
            "acknowledgements": [],
        },
        workspace_id="workspace-b",
    )
    sync_contexts: list[dict[str, object]] = []

    class _Response:
        def __init__(self, payload: dict[str, object]) -> None:
            self._payload = payload

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def read(self) -> bytes:
            return json.dumps(self._payload).encode("utf-8")

    def _fake_urlopen(request, timeout):
        if request.full_url.endswith("/api/v1/guard/events"):
            return _Response({"accepted": 0, "rejected": 0, "statuses": []})
        body = json.loads(request.data.decode("utf-8")) if request.data else {}
        if isinstance(body, dict) and isinstance(body.get("syncContext"), dict):
            sync_contexts.append(body["syncContext"])
        return _Response(
            {
                "syncedAt": "2026-06-05T13:30:01+00:00",
                "receiptsStored": 0,
                "policyBundle": bundle,
            }
        )

    stub_authenticated_urlopen(monkeypatch, _fake_urlopen)
    monkeypatch.setattr(runner, "sync_pain_signals", lambda _store, auth_context=None: 0)

    runner.sync_receipts(store)

    assert store.get_sync_payload("policy_bundle") is None
    stored = store.get_sync_payload("policy_bundle_ack")
    assert isinstance(stored, dict)
    assert stored["status"] == "failed"
    assert stored["bundleHash"] == bundle["bundleHash"]
    assert stored["bundleVersion"] == bundle["bundleVersion"]
    assert "policyBundleAcknowledgement" not in sync_contexts[0]
    assert sync_contexts[-1]["policyBundleAcknowledgement"] == stored
