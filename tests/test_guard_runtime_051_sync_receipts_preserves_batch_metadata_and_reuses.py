"""Runtime regression tests: sync receipts preserves batch metadata and reuses."""

from __future__ import annotations

from tests.guard_runtime_test_dependencies import (
    GuardReceipt,
    GuardStore,
    Path,
    guard_runner_module,
    json,
    policy_bundle_acknowledgement_payload,
    policy_bundle_test_keyring,
    policy_bundle_test_verification_key,
    pytest,
    sign_policy_bundle,
    stub_authenticated_urlopen,
    validated_policy_bundle_payload,
)
from tests.guard_runtime_test_support import (
    _cache_signed_test_policy_bundle,
    _seed_guard_cloud,
)
from tests.guard_runtime_test_support import (
    _isolate_codex_runtime_marker as _isolate_codex_runtime_marker,
)


def test_sync_receipts_preserves_batch_metadata_and_reuses_device_metadata(tmp_path, monkeypatch):
    store = GuardStore(tmp_path / "guard-home")
    _seed_guard_cloud(store, workspace_id="workspace-1")
    store.set_sync_payload("policy_bundle_keyring", policy_bundle_test_keyring(), "2026-04-19T00:00:00Z")
    for index in range(65):
        store.add_receipt(
            GuardReceipt(
                receipt_id=f"receipt-{index}",
                timestamp="2026-04-19T00:00:00+00:00",
                harness="codex",
                artifact_id=f"artifact-{index}",
                artifact_hash=f"sha256:{index:064x}",
                policy_decision="review",
                capabilities_summary="requests file write",
                changed_capabilities=("fs_write",),
                provenance_summary="local codex workspace",
                artifact_name=f"artifact-{index}",
                source_scope="workspace",
            )
        )

    metadata_calls: list[bool] = []
    monkeypatch.setattr(
        guard_runner_module,
        "_guard_device_metadata",
        lambda _store: metadata_calls.append(True) or ("device-1", "MacBook Pro"),
    )
    monkeypatch.setattr(guard_runner_module, "sync_pain_signals", lambda _store, auth_context=None: 0)

    sync_payloads = iter(
        [
            {
                "syncedAt": "2026-04-19T00:00:10+00:00",
                "receiptsStored": 50,
                "advisories": [
                    {
                        "artifactId": "artifact-a",
                        "artifactName": "Artifact A",
                        "severity": "high",
                        "reason": "Batch one advisory",
                    }
                ],
                "policy": {"mode": "enforce"},
                "policyBundle": {
                    "contractVersion": "guard-policy-bundle.v1",
                    "bundleVersion": "policy-2026-04-19.1",
                    "bundleHash": "",
                    "issuedAt": "2026-04-19T00:00:10+00:00",
                    "expiresAt": None,
                    "verifier": {
                        "algorithm": "rsa-pss-sha256",
                        "keyId": "guard-policy-bundle-v1",
                        "signature": None,
                    },
                    "rolloutState": "enforcing",
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
                    "acknowledgements": [
                        {
                            "deviceId": "device-1",
                            "deviceName": "Guard local daemon",
                            "acknowledgedAt": "2026-04-19T00:00:11+00:00",
                            "status": "synced",
                        }
                    ],
                },
                "alertPreferences": {"advisoriesEnabled": True},
                "teamPolicyPack": {
                    "name": "Team policy",
                    "blockedArtifacts": ["blocked-one"],
                    "allowedPublishers": ["trusted-one"],
                },
                "exceptions": [
                    {
                        "scope": "artifact",
                        "harness": "*",
                        "artifactId": "allowed-one",
                        "artifactName": "Allowed One",
                        "reason": "Batch one exception",
                        "owner": "owner@example.com",
                        "expiresAt": "2026-04-19T06:00:00+00:00",
                    }
                ],
            },
            {
                "syncedAt": "2026-04-19T00:00:11+00:00",
                "receiptsStored": 15,
                "advisories": [
                    {
                        "artifactId": "artifact-b",
                        "artifactName": "Artifact B",
                        "severity": "medium",
                        "reason": "Batch two advisory",
                    }
                ],
                "policy": {},
                "alertPreferences": {"advisoriesEnabled": True},
                "teamPolicyPack": {
                    "name": "Team policy",
                    "blockedArtifacts": ["blocked-two"],
                    "allowedPublishers": ["trusted-two"],
                },
                "exceptions": [
                    {
                        "scope": "artifact",
                        "harness": "*",
                        "artifactId": "allowed-two",
                        "artifactName": "Allowed Two",
                        "reason": "Batch two exception",
                        "owner": "owner@example.com",
                        "expiresAt": "2026-04-19T08:00:00+00:00",
                    }
                ],
            },
        ]
    )
    sync_payloads_list = list(sync_payloads)
    first_bundle = sync_payloads_list[0]["policyBundle"]
    if isinstance(first_bundle, dict):
        first_bundle = sign_policy_bundle(first_bundle)
        sync_payloads_list[0]["policyBundle"] = first_bundle
    sync_payloads = iter(sync_payloads_list)

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
        payload = json.loads(request.data.decode("utf-8"))
        if request.full_url.endswith("/api/v1/guard/events"):
            return _Response({"accepted": 0, "rejected": 0, "statuses": []})
        assert len(payload["receipts"]) in {50, 15}
        return _Response(next(sync_payloads))

    stub_authenticated_urlopen(monkeypatch, _fake_urlopen)

    payload = guard_runner_module.sync_receipts(store)

    assert metadata_calls == [True]
    assert payload["receipts_stored"] == 65
    assert payload["advisories_stored"] == 2
    assert payload["exceptions_stored"] == 0
    assert payload["remote_policies_stored"] == 0
    assert store.get_sync_payload("policy") == {}
    assert store.get_sync_payload("team_policy_pack") == {}
    assert store.get_sync_payload("policy_bundle") == first_bundle
    assert store.get_sync_payload("policy_bundle_ack") == {
        "appliedAt": "2026-04-19T00:00:11+00:00",
        "bundleHash": store.get_sync_payload("policy_bundle")["bundleHash"],
        "bundleVersion": "policy-2026-04-19.1",
        "deviceId": "device-1",
        "deviceName": "MacBook Pro",
        "status": "synced",
    }
    assert {item["artifactId"] for item in store.list_cached_advisories(limit=None)} == {"artifact-a", "artifact-b"}
    assert store.list_policy_decisions() == []
    assert store.list_cloud_exceptions() == []
    assert len(store.list_events(event_name="premium_advisory")) == 2
    assert len(store.list_events(event_name="exception_expiring")) == 0


def test_policy_bundle_validation_rejects_tampered_hash():
    bundle = {
        "contractVersion": "guard-policy-bundle.v1",
        "bundleVersion": "policy-2026-04-19.1",
        "bundleHash": "",
        "issuedAt": "2026-04-19T00:00:10+00:00",
        "expiresAt": None,
        "verifier": {
            "algorithm": "rsa-pss-sha256",
            "keyId": "guard-policy-bundle-v1",
            "signature": None,
        },
        "rolloutState": "enforcing",
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
        "rules": [
            {
                "ruleId": "pkg-block",
                "action": "block",
                "reason": "Block risky package installs before execution.",
                "matcherFamilies": ["package-request"],
                "scope": {
                    "agents": [],
                    "devices": [],
                    "ecosystems": ["npm"],
                    "environments": ["development"],
                    "harnesses": ["codex"],
                    "locations": [],
                },
            }
        ],
        "acknowledgements": [],
    }

    signing_key = policy_bundle_test_verification_key()
    bundle = sign_policy_bundle(bundle, key=signing_key)
    bundle["bundleHash"] = "sha256:tampered"
    validated_bundle, reason = validated_policy_bundle_payload(
        bundle,
        trusted_verification_keys=(signing_key,),
        anchored_verification_keys=(signing_key,),
        expected_workspace_id="workspace-1",
    )

    assert validated_bundle is None
    assert reason == "bundle_hash_mismatch"


def test_receipt_sync_context_uploads_policy_bundle_acknowledgement(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    _cache_signed_test_policy_bundle(store, [])
    policy_bundle = store.get_sync_payload("policy_bundle")
    assert isinstance(policy_bundle, dict)
    device_id, device_name = guard_runner_module._guard_device_metadata(store)
    acknowledgement = policy_bundle_acknowledgement_payload(
        device_id=device_id,
        device_name=device_name,
        policy_bundle=policy_bundle,
        synced_at="2026-04-19T00:00:11+00:00",
    )
    store.set_sync_payload(
        "policy_bundle_ack",
        acknowledgement,
        "2026-04-19T00:00:11+00:00",
    )

    context = guard_runner_module._receipt_sync_context(
        store,
        local_guard_online_at="2026-04-19T00:01:00+00:00",
    )

    assert context["policyBundleAcknowledgement"] == acknowledgement


@pytest.mark.parametrize(
    ("field", "invalid_value"),
    [
        ("bundleHash", "sha256:stale"),
        ("bundleVersion", "policy-stale"),
        ("deviceId", "wrong-device-id"),
        ("deviceName", "Wrong device name"),
        ("status", "pending"),
        ("appliedAt", ""),
        ("appliedAt", "not-a-timestamp"),
    ],
)
def test_receipt_sync_context_omits_invalid_policy_bundle_acknowledgement(
    tmp_path: Path,
    field: str,
    invalid_value: str,
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    _cache_signed_test_policy_bundle(store, [])
    policy_bundle = store.get_sync_payload("policy_bundle")
    assert isinstance(policy_bundle, dict)
    device_id, device_name = guard_runner_module._guard_device_metadata(store)
    acknowledgement = policy_bundle_acknowledgement_payload(
        device_id=device_id,
        device_name=device_name,
        policy_bundle=policy_bundle,
        synced_at="2026-04-19T00:00:11+00:00",
    )
    acknowledgement[field] = invalid_value
    store.set_sync_payload(
        "policy_bundle_ack",
        acknowledgement,
        "2026-04-19T00:00:11+00:00",
    )

    context = guard_runner_module._receipt_sync_context(
        store,
        local_guard_online_at="2026-04-19T00:01:00+00:00",
    )

    assert "policyBundleAcknowledgement" not in context


def test_receipt_sync_context_omits_acknowledgement_for_untrusted_cached_bundle(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    _cache_signed_test_policy_bundle(store, [])
    policy_bundle = store.get_sync_payload("policy_bundle")
    assert isinstance(policy_bundle, dict)
    device_id, device_name = guard_runner_module._guard_device_metadata(store)
    acknowledgement = policy_bundle_acknowledgement_payload(
        device_id=device_id,
        device_name=device_name,
        policy_bundle=policy_bundle,
        synced_at="2026-04-19T00:00:11+00:00",
    )
    store.set_sync_payload(
        "policy_bundle_ack",
        acknowledgement,
        "2026-04-19T00:00:11+00:00",
    )
    policy_defaults = policy_bundle.get("policyDefaults")
    assert isinstance(policy_defaults, dict)
    tampered_policy_bundle = dict(policy_bundle)
    tampered_policy_bundle["policyDefaults"] = {
        **policy_defaults,
        "mode": "monitor",
    }
    store.set_sync_payload(
        "policy_bundle",
        tampered_policy_bundle,
        "2026-04-19T00:00:12+00:00",
    )

    context = guard_runner_module._receipt_sync_context(
        store,
        local_guard_online_at="2026-04-19T00:01:00+00:00",
    )

    assert "policyBundleAcknowledgement" not in context


def test_policy_bundle_validation_rejects_missing_rules_field():
    bundle = {
        "contractVersion": "guard-policy-bundle.v1",
        "bundleVersion": "policy-2026-04-19.1",
        "bundleHash": "sha256:placeholder",
        "issuedAt": "2026-04-19T00:00:10+00:00",
        "expiresAt": None,
        "verifier": {
            "algorithm": "rsa-pss-sha256",
            "keyId": "guard-policy-bundle-v1",
            "signature": None,
        },
        "rolloutState": "enforcing",
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
        "acknowledgements": [],
    }

    validated_bundle, reason = validated_policy_bundle_payload(bundle)

    assert validated_bundle is None
    assert reason == "missing_required_field"
