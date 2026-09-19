"""Runtime regression tests: simulate policy bundle receipts replays recent receipts."""

from __future__ import annotations

from tests.guard_runtime_test_dependencies import (
    GuardReceipt,
    GuardStore,
    PolicyDecision,
    guard_runner_module,
    payload_hash_for_policy_bundle,
    policy_bundle_test_keyring,
    sign_policy_bundle,
)
from tests.guard_runtime_test_support import (
    _cache_signed_test_policy_bundle,
    _seed_guard_cloud,
    _signed_test_policy_bundle,
)
from tests.guard_runtime_test_support import (
    _isolate_codex_runtime_marker as _isolate_codex_runtime_marker,
)


def test_simulate_policy_bundle_receipts_replays_recent_receipts_without_enforcing(tmp_path):
    store = GuardStore(tmp_path / "guard-home")
    store.add_receipt(
        GuardReceipt(
            receipt_id="receipt-package",
            timestamp="2026-06-05T13:25:00+00:00",
            harness="codex",
            artifact_id="codex:project:package-request:abc",
            artifact_hash="sha256:package",
            policy_decision="review",
            capabilities_summary="package install request",
            changed_capabilities=("package-request",),
            provenance_summary="local package install",
            artifact_name="npm install minimist",
            source_scope="project",
        )
    )
    store.add_receipt(
        GuardReceipt(
            receipt_id="receipt-file",
            timestamp="2026-06-05T13:26:00+00:00",
            harness="codex",
            artifact_id="codex:project:file-read:def",
            artifact_hash="sha256:file",
            policy_decision="review",
            capabilities_summary="file read request",
            changed_capabilities=("file-read",),
            provenance_summary="local file read",
            artifact_name="open config",
            source_scope="project",
        )
    )
    bundle = {
        "bundleVersion": "policy-2026-06-05.3",
        "bundleHash": "sha256:bundle-proof",
        "expiresAt": None,
        "rules": [
            {
                "ruleId": "pkg-block",
                "action": "block",
                "reason": "Block risky package installs.",
                "artifactType": "package_request",
                "matcherFamilies": ["package-request"],
                "scope": {
                    "agents": [],
                    "devices": [],
                    "ecosystems": [],
                    "environments": ["development"],
                    "harnesses": ["codex"],
                    "locations": [],
                },
            },
            {
                "ruleId": "file-allow",
                "action": "allow",
                "reason": "Allow benign file reads.",
                "matcherFamilies": ["file-read"],
                "scope": {
                    "agents": [],
                    "devices": [],
                    "ecosystems": [],
                    "environments": ["development"],
                    "harnesses": ["codex"],
                    "locations": [],
                },
            },
        ],
    }

    simulation = guard_runner_module.simulate_policy_bundle_receipts(
        store,
        bundle,
        now="2026-06-05T13:30:00+00:00",
    )

    assert simulation["policy_bundle_version"] == "policy-2026-06-05.3"
    assert simulation["policy_version"] == "sha256:bundle-proof"
    assert simulation["summary"] == {
        "allow": 1,
        "block": 1,
        "review": 0,
        "ignore": 0,
        "matched": 2,
        "unchanged": 0,
    }
    assert simulation["matches"] == [
        {
            "receipt_id": "receipt-file",
            "artifact_id": "codex:project:file-read:def",
            "harness": "codex",
            "matcher_family": "file-read",
            "observed_action": "review",
            "simulated_action": "allow",
            "matched_rule_id": "file-allow",
            "policy_version": "sha256:bundle-proof",
            "timestamp": "2026-06-05T13:26:00+00:00",
        },
        {
            "receipt_id": "receipt-package",
            "artifact_id": "codex:project:package-request:abc",
            "harness": "codex",
            "matcher_family": "package-request",
            "observed_action": "review",
            "simulated_action": "block",
            "matched_rule_id": "pkg-block",
            "policy_version": "sha256:bundle-proof",
            "timestamp": "2026-06-05T13:25:00+00:00",
        },
    ]


def test_simulate_policy_bundle_receipts_reports_event_freshness(tmp_path):
    store = GuardStore(tmp_path / "guard-home")
    store.add_receipt(
        GuardReceipt(
            receipt_id="receipt-old",
            timestamp="2026-06-01T10:00:00+00:00",
            harness="codex",
            artifact_id="codex:project:package-request:old",
            artifact_hash="sha256:old",
            policy_decision="review",
            capabilities_summary="old package request",
            changed_capabilities=("package-request",),
            provenance_summary="older request",
            artifact_name="old install",
            source_scope="project",
        )
    )

    simulation = guard_runner_module.simulate_policy_bundle_receipts(
        store,
        {"bundleVersion": "policy-2026-06-05.3", "bundleHash": "sha256:bundle-proof", "rules": []},
        now="2026-06-05T13:30:00+00:00",
    )

    assert simulation["event_freshness"] == {
        "latest_receipt_at": "2026-06-01T10:00:00+00:00",
        "oldest_receipt_at": "2026-06-01T10:00:00+00:00",
        "sampled_receipts": 1,
        "stale": True,
    }


def test_simulate_policy_bundle_receipts_clamps_unknown_actions_to_review(tmp_path):
    store = GuardStore(tmp_path / "guard-home")
    store.add_receipt(
        GuardReceipt(
            receipt_id="receipt-warn",
            timestamp="2026-06-05T13:25:00+00:00",
            harness="codex",
            artifact_id="codex:project:file-read:warn",
            artifact_hash="sha256:warn",
            policy_decision="warn",
            capabilities_summary="warn receipt",
            changed_capabilities=("file-read",),
            provenance_summary="warn fallback",
            artifact_name="warn receipt",
            source_scope="project",
        )
    )

    simulation = guard_runner_module.simulate_policy_bundle_receipts(
        store,
        {"bundleVersion": "policy-2026-06-05.3", "bundleHash": "sha256:bundle-proof", "rules": []},
        now="2026-06-05T13:30:00+00:00",
    )

    assert simulation["summary"] == {
        "allow": 0,
        "block": 0,
        "review": 1,
        "ignore": 0,
        "matched": 0,
        "unchanged": 1,
    }
    assert simulation["matches"][0]["simulated_action"] == "review"


def test_policy_bundle_version_persists_after_store_reopen(tmp_path):
    home = tmp_path / "guard-home"
    store = GuardStore(home)
    store.set_sync_payload(
        "policy_bundle",
        {
            "bundleVersion": "policy-2026-06-05.1",
            "bundleHash": "sha256:bundle-proof",
            "issuedAt": "2026-06-05T13:30:00+00:00",
        },
        "2026-06-05T13:30:00+00:00",
    )

    reopened = GuardStore(home)

    assert reopened.get_sync_payload("policy_bundle") == {
        "bundleVersion": "policy-2026-06-05.1",
        "bundleHash": "sha256:bundle-proof",
        "issuedAt": "2026-06-05T13:30:00+00:00",
    }


def test_cached_policy_bundle_revalidation_rejects_expired_last_known_good(tmp_path):
    store = GuardStore(tmp_path / "guard-home")
    _seed_guard_cloud(store, workspace_id="workspace-1")
    store.set_sync_payload("policy_bundle_keyring", policy_bundle_test_keyring(), "2026-04-19T00:00:00Z")
    expired_bundle = {
        "contractVersion": "guard-policy-bundle.v1",
        "bundleVersion": "policy-2020-01-01.1",
        "bundleHash": "",
        "issuedAt": "2020-01-01T00:00:00Z",
        "expiresAt": "2020-01-02T00:00:00Z",
        "verifier": {},
        "rolloutState": "enforcing",
        "policyDefaults": {
            "mode": "enforce",
            "defaultAction": "block",
            "unknownPublisherAction": "block",
            "changedHashAction": "block",
            "newNetworkDomainAction": "block",
            "subprocessAction": "block",
            "telemetryEnabled": False,
            "syncEnabled": True,
        },
        "rules": [],
        "acknowledgements": [],
    }
    expired_bundle = sign_policy_bundle(expired_bundle)
    store.set_sync_payload("policy_bundle_last_good", expired_bundle, "2020-01-01T00:00:00Z")

    validated, reason = guard_runner_module._validate_cached_policy_bundle(store, expired_bundle)

    assert validated is None
    assert reason == "bundle_expired"


def test_cached_and_last_good_policy_bundle_preserve_signed_empty_optional_fields(tmp_path):
    store = GuardStore(tmp_path / "guard-home")
    _cache_signed_test_policy_bundle(store, [])
    policy_bundle = store.get_sync_payload("policy_bundle")
    assert isinstance(policy_bundle, dict)
    policy_bundle["cloudExceptions"] = []
    policy_bundle["receiptRedactionLevel"] = "partial"
    policy_bundle = sign_policy_bundle(policy_bundle)
    store.set_sync_payload("policy_bundle", policy_bundle, "2026-01-01T00:00:00Z")
    store.set_sync_payload("policy_bundle_last_good", policy_bundle, "2026-01-01T00:00:00Z")

    cached, cached_reason = guard_runner_module._validate_cached_policy_bundle(
        store,
        store.get_sync_payload("policy_bundle"),
    )
    last_good, last_good_reason = guard_runner_module._validate_cached_policy_bundle(
        store,
        store.get_sync_payload("policy_bundle_last_good"),
    )

    assert cached_reason is None
    assert cached == policy_bundle
    assert last_good_reason is None
    assert last_good == policy_bundle


def test_materialized_policy_bundle_decision_requires_current_cached_signature(tmp_path):
    store = GuardStore(tmp_path / "guard-home")
    _seed_guard_cloud(store, workspace_id="workspace-1")
    store.set_sync_payload("policy_bundle_keyring", policy_bundle_test_keyring(), "2026-04-19T00:00:00Z")
    store.replace_remote_policies(
        [
            PolicyDecision(
                harness="codex",
                scope="harness",
                action="allow",
                artifact_id="family:package-request",
                source="policy-bundle",
                owner="signed-package-allow",
                reason="Test-only signed policy decision.",
            )
        ],
        "2026-04-19T00:00:00Z",
        remote_write_authorized=True,
    )
    policy_bundle = sign_policy_bundle(
        {
            "contractVersion": "guard-policy-bundle.v1",
            "bundleVersion": "policy-2026-04-19.1",
            "issuedAt": "2026-04-19T00:00:00Z",
            "expiresAt": None,
            "verifier": {},
            "rolloutState": "enforcing",
            "policyDefaults": {
                "mode": "enforce",
                "defaultAction": "block",
                "unknownPublisherAction": "block",
                "changedHashAction": "block",
                "newNetworkDomainAction": "block",
                "subprocessAction": "block",
                "telemetryEnabled": False,
                "syncEnabled": True,
            },
            "rules": [
                {
                    "ruleId": "signed-package-allow",
                    "action": "allow",
                    "reason": "Test-only signed policy decision.",
                    "artifactType": "package_request",
                    "matcherFamilies": ["package-request"],
                    "scope": {"harnesses": ["codex"], "ecosystems": []},
                }
            ],
            "acknowledgements": [],
        }
    )
    digest_bundle = dict(policy_bundle)
    digest_bundle["verifier"] = {
        "algorithm": "sha256",
        "keyId": "legacy-digest-only",
        "signature": None,
    }
    digest_bundle["bundleHash"] = guard_runner_module._computed_policy_bundle_hash(digest_bundle)
    digest_bundle["payloadHash"] = payload_hash_for_policy_bundle(digest_bundle)
    digest_bundle["verifier"]["signature"] = digest_bundle["payloadHash"]
    store.set_sync_payload("policy_bundle", digest_bundle, "2026-04-19T00:00:00Z")

    assert store.resolve_policy("codex", "codex:project:package-request:test", "sha256:test") is None

    store.set_sync_payload("policy_bundle", policy_bundle, "2026-04-19T00:00:01Z")

    assert store.resolve_policy("codex", "codex:project:package-request:test", "sha256:test") == "allow"


def test_materialized_policy_bundle_decision_must_exist_in_current_signed_bundle(tmp_path):
    store = GuardStore(tmp_path / "guard-home")
    _cache_signed_test_policy_bundle(store, [])
    store.replace_remote_policies(
        [
            PolicyDecision(
                harness="codex",
                scope="harness",
                action="allow",
                artifact_id="family:package-request",
                source="policy-bundle",
                owner="absent-signed-rule",
                reason="This materialized allow is not present in the signed bundle.",
            )
        ],
        "2026-01-01T00:00:00Z",
        remote_write_authorized=True,
    )

    assert store.resolve_policy("codex", "codex:project:package-request:test", "sha256:test") is None


def test_policy_bundle_replacement_invalidates_prevalidated_allow_claim(tmp_path):
    store = GuardStore(tmp_path / "guard-home")
    _seed_guard_cloud(store, workspace_id="workspace-1")
    store.set_sync_payload(
        "policy_bundle_keyring",
        policy_bundle_test_keyring(workspace_id="workspace-1"),
        "2026-01-01T00:00:00Z",
    )
    allow_rule = {
        "ruleId": "package-allow-before-replacement",
        "action": "allow",
        "reason": "Test-only signed package allow.",
        "artifactType": "package_request",
        "matcherFamilies": ["package-request"],
        "scope": {
            "agents": [],
            "devices": [],
            "ecosystems": [],
            "environments": ["development"],
            "harnesses": ["codex"],
            "locations": [],
        },
    }
    authorized_bundle = _signed_test_policy_bundle([allow_rule])
    store.set_sync_payload("policy_bundle", authorized_bundle, "2026-01-01T00:00:00Z")
    store.replace_remote_policies(
        guard_runner_module._build_policy_bundle_decisions(
            authorized_bundle,
            device_id=guard_runner_module._guard_device_metadata(store)[0],
            device_name=guard_runner_module._guard_device_metadata(store)[1],
        ),
        "2026-01-01T00:00:00Z",
        remote_write_authorized=True,
    )
    artifact_id = "codex:project:package-request:claim-race"
    lookup = store.resolve_policy_decision_lookup(
        "codex",
        artifact_id,
        "sha256:claim-race",
        now="2026-01-01T00:01:00Z",
        consume_one_shot=False,
    )
    selected = lookup["decision"]
    assert selected is not None
    assert selected["action"] == "allow"
    assert store.claim_approval_reuse_decision(
        selected,
        now="2026-01-01T00:02:00Z",
    )

    replacement_bundle = _signed_test_policy_bundle(
        [],
        bundle_version="policy-2026-01-02.1",
        issued_at="2026-01-02T00:00:00Z",
    )
    store.set_sync_payload("policy_bundle", replacement_bundle, "2026-01-02T00:00:00Z")

    assert not store.claim_approval_reuse_decision(
        selected,
        now="2026-01-02T00:01:00Z",
    )
