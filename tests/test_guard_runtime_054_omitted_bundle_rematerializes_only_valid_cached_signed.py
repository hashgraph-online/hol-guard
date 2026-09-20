"""Runtime regression tests: omitted bundle rematerializes only valid cached signed."""

from __future__ import annotations

from tests.guard_runtime_test_dependencies import (
    GuardStore,
    Path,
    PolicyDecision,
    guard_runner_module,
    json,
    payload_hash_for_policy_bundle,
    policy_bundle_test_keyring,
    pytest,
    stub_authenticated_urlopen,
)
from tests.guard_runtime_test_support import (
    _cache_signed_test_policy_bundle,
    _seed_guard_cloud,
    _signed_test_package_block_bundle,
    _signed_test_policy_bundle,
)
from tests.guard_runtime_test_support import (
    _isolate_codex_runtime_marker as _isolate_codex_runtime_marker,
)


def test_omitted_bundle_rematerializes_only_valid_cached_signed_policy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    _seed_guard_cloud(store, workspace_id="workspace-1")
    store.set_sync_payload(
        "policy_bundle_keyring",
        policy_bundle_test_keyring(workspace_id="workspace-1"),
        "2026-07-17T00:00:00Z",
    )
    cached_bundle = _signed_test_package_block_bundle(
        bundle_version="policy-2026-07-17.3",
        issued_at="2026-07-17T00:00:00Z",
    )
    store.set_sync_payload("policy_bundle", cached_bundle, "2026-07-17T00:00:00Z")
    store.set_sync_payload(
        "policy",
        {"mode": "observe", "defaultAction": "allow"},
        "2026-07-17T00:00:00Z",
    )
    store.set_sync_payload(
        "team_policy_pack",
        {"name": "Stale unsigned policy", "allowedPublishers": ["stale.publisher.example"]},
        "2026-07-17T00:00:00Z",
    )
    store.replace_remote_policies(
        [
            PolicyDecision(
                harness="*",
                scope="artifact",
                action="allow",
                artifact_id="stale-cloud-allow",
                source="cloud-sync",
            ),
            PolicyDecision(
                harness="*",
                scope="publisher",
                action="allow",
                publisher="stale.publisher.example",
                source="team-policy",
            ),
            PolicyDecision(
                harness="*",
                scope="artifact",
                action="allow",
                artifact_id="stale-bundle-allow",
                owner="stale-unsigned-row",
                source="policy-bundle",
            ),
        ],
        "2026-07-17T00:00:00Z",
        remote_write_authorized=True,
    )
    store.set_cloud_exceptions(
        [
            {
                "id": "stale-receipt-sync-exception",
                "effect": "allow",
                "scope": "artifact",
                "harness": "*",
                "owner": "attacker@example.com",
                "expiry": "2099-01-01T00:00:00+00:00",
                "provenance": "receipt-sync",
            }
        ],
        "2026-07-17T00:00:00Z",
    )
    response_payload: dict[str, object] = {
        "syncedAt": "2026-07-17T00:00:01Z",
        "receiptsStored": 0,
        "policy": {"mode": "observe", "defaultAction": "allow"},
        "teamPolicyPack": {
            "name": "New unsigned policy",
            "allowedPublishers": ["new.publisher.example"],
        },
        "exceptions": [
            {
                "exceptionId": "new-unsigned-exception",
                "scope": "artifact",
                "harness": "*",
                "artifactId": "new-unsigned-allow",
                "owner": "attacker@example.com",
                "expiresAt": "2099-01-01T00:00:00Z",
            }
        ],
    }

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
        return _Response(response_payload)

    stub_authenticated_urlopen(monkeypatch, _fake_urlopen)
    monkeypatch.setattr(guard_runner_module, "sync_pain_signals", lambda _store, auth_context=None: 0)

    summary = guard_runner_module.sync_receipts(store)

    assert store.get_sync_payload("policy_bundle") == cached_bundle
    assert store.get_sync_payload("policy_bundle_last_error") == {}
    assert store.get_sync_payload("policy") == {}
    assert store.get_sync_payload("team_policy_pack") == {}
    assert [
        (item["harness"], item["scope"], item["artifact_id"], item["action"], item["owner"], item["source"])
        for item in store.list_policy_decisions()
    ] == [("codex", "harness", "family:package-request", "block", "signed-package-block", "policy-bundle")]
    assert store.list_cloud_exceptions() == []
    assert store.resolve_policy("codex", "codex:project:package-request:cached-current", "hash") == "block"
    assert store.resolve_policy("codex", "stale-cloud-allow", "hash") is None
    assert store.resolve_policy("codex", "stale-bundle-allow", "hash") is None
    assert store.resolve_policy("codex", "new-unsigned-allow", "hash") is None
    assert store.resolve_policy("codex", "other", "hash", publisher="stale.publisher.example") is None
    assert store.resolve_policy("codex", "other", "hash", publisher="new.publisher.example") is None
    assert summary["exceptions_stored"] == 0
    assert summary["cloud_exceptions_stored"] == 0
    assert summary["remote_policies_stored"] == 1


def test_invalid_refresh_preserves_newer_current_bundle_after_interrupted_last_good_write(
    tmp_path,
    monkeypatch,
):
    store = GuardStore(tmp_path / "guard-home")
    _seed_guard_cloud(store, workspace_id="workspace-1")
    store.set_sync_payload(
        "policy_bundle_keyring",
        policy_bundle_test_keyring(workspace_id="workspace-1"),
        "2026-01-01T00:00:00Z",
    )
    old_allow_rule = {
        "ruleId": "old-package-allow",
        "action": "allow",
        "reason": "This superseded rule must not regain authority.",
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
    old_bundle = _signed_test_policy_bundle(
        [old_allow_rule],
        bundle_version="policy-2026-01-01.1",
        issued_at="2026-01-01T00:00:00Z",
    )
    newer_current_bundle = _signed_test_policy_bundle(
        [],
        bundle_version="policy-2026-01-02.1",
        issued_at="2026-01-02T00:00:00Z",
    )
    invalid_refresh = dict(newer_current_bundle)
    invalid_refresh["bundleVersion"] = "policy-2026-01-03.1"
    invalid_refresh["issuedAt"] = "2026-01-03T00:00:00Z"
    invalid_refresh["verifier"] = {
        "algorithm": "sha256",
        "keyId": "attacker-recomputed-digest",
        "signature": None,
    }
    invalid_refresh["bundleHash"] = guard_runner_module._computed_policy_bundle_hash(invalid_refresh)
    invalid_refresh["payloadHash"] = payload_hash_for_policy_bundle(invalid_refresh)
    invalid_refresh["verifier"]["signature"] = invalid_refresh["payloadHash"]
    responses = iter(
        [
            {
                "syncedAt": "2026-01-01T00:00:01Z",
                "receiptsStored": 0,
                "policyBundle": old_bundle,
            },
            {
                "syncedAt": "2026-01-03T00:00:01Z",
                "receiptsStored": 0,
                "policyBundle": invalid_refresh,
            },
        ]
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

    def _fake_urlopen(request, timeout):
        if request.full_url.endswith("/api/v1/guard/events"):
            return _Response({"accepted": 0, "rejected": 0, "statuses": []})
        return _Response(next(responses))

    stub_authenticated_urlopen(monkeypatch, _fake_urlopen)
    monkeypatch.setattr(guard_runner_module, "sync_pain_signals", lambda _store, auth_context=None: 0)

    guard_runner_module.sync_receipts(store)
    artifact_id = "codex:project:package-request:interrupted"
    assert store.resolve_policy("codex", artifact_id, "hash") == "allow"

    # Simulate interruption after the newer verified current bundle was stored,
    # but before last-good and materialized policy rows were updated.
    store.set_sync_payload("policy_bundle", newer_current_bundle, "2026-01-02T00:00:00Z")
    assert store.get_sync_payload("policy_bundle_last_good") == old_bundle
    assert store.resolve_policy("codex", artifact_id, "hash") is None

    guard_runner_module.sync_receipts(store)

    assert store.get_sync_payload("policy_bundle") == newer_current_bundle
    assert store.get_sync_payload("policy_bundle_last_good") == old_bundle
    assert store.resolve_policy("codex", artifact_id, "hash") is None
    assert not any(
        item["source"] == "policy-bundle" and item["action"] == "allow" for item in store.list_policy_decisions()
    )
    assert store.get_sync_payload("policy_bundle_last_error")["reason"] == "unsupported_signature_algorithm"


def test_policy_bundle_decisions_map_to_runtime_families(tmp_path):
    store = GuardStore(tmp_path / "guard-home")
    bundle = {
        "bundleVersion": "policy-2026-04-19.2",
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
                "ruleId": "mcp-review",
                "action": "review",
                "reason": "Review MCP server calls.",
                "matcherFamilies": ["mcp"],
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
            {
                "ruleId": "shell-block",
                "action": "block",
                "reason": "Block destructive shell actions.",
                "matcherFamilies": ["tool-action"],
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

    decisions = guard_runner_module._build_policy_bundle_decisions(
        bundle,
        device_id=guard_runner_module._guard_device_metadata(store)[0],
        device_name="MacBook Pro",
    )
    store.replace_remote_policies(decisions, "2026-04-19T00:00:11+00:00", remote_write_authorized=True)
    _cache_signed_test_policy_bundle(store, bundle["rules"])

    assert store.resolve_policy("codex", "codex:project:package-request:abc", "hash") == "block"
    assert store.resolve_policy("codex", "codex:project:mcp:shell", "hash") == "review"
    assert store.resolve_policy("codex", "codex:project:file-read:abc", "hash") == "allow"
    assert store.resolve_policy("codex", "codex:project:tool-action:abc", "hash") == "block"


def test_policy_bundle_exact_artifact_rules_apply_with_workspace_scope(tmp_path):
    store = GuardStore(tmp_path / "guard-home")
    workspace_a = str(tmp_path / "workspace-a")
    workspace_b = str(tmp_path / "workspace-b")
    allow_artifact = "codex:project:tool-action:deploy-prod"
    block_artifact = "codex:project:file-read:secret-env"
    bundle = {
        "bundleVersion": "policy-2026-06-05.9",
        "expiresAt": "2026-12-01T00:00:00+00:00",
        "rules": [
            {
                "ruleId": "memory-allow-deploy",
                "action": "allow",
                "reason": "Approved Suggested Memory for this deploy command.",
                "matcher": {"artifactId": allow_artifact},
                "scope": {
                    "agents": [],
                    "devices": [],
                    "environments": ["development"],
                    "harnesses": ["codex"],
                    "locations": [workspace_a],
                },
                "sourceDecisionId": "decision-allow",
                "sourceSuggestionId": "suggestion-allow",
            },
            {
                "ruleId": "memory-block-secret",
                "action": "block",
                "reason": "Blocked Suggested Memory for secret reads.",
                "matcher": {"artifact_id": block_artifact},
                "scope": {
                    "agents": [],
                    "devices": [],
                    "environments": ["development"],
                    "harnesses": ["codex"],
                    "locations": [workspace_a],
                },
                "expiresAt": "2026-10-01T00:00:00+00:00",
                "sourceDecisionId": "decision-block",
                "sourceSuggestionId": "suggestion-block",
            },
        ],
    }

    decisions = guard_runner_module._build_policy_bundle_decisions(
        bundle,
        device_id=guard_runner_module._guard_device_metadata(store)[0],
        device_name="MacBook Pro",
    )
    store.replace_remote_policies(decisions, "2026-06-05T13:31:00+00:00", remote_write_authorized=True)
    _cache_signed_test_policy_bundle(
        store,
        bundle["rules"],
        bundle_version=str(bundle["bundleVersion"]),
        expires_at=str(bundle["expiresAt"]),
    )

    assert store.resolve_policy("codex", allow_artifact, "hash", workspace=workspace_a) == "allow"
    assert store.resolve_policy("codex", block_artifact, "hash", workspace=workspace_a) == "block"
    assert store.resolve_policy("codex", "codex:project:tool-action:other", "hash", workspace=workspace_a) is None
    assert store.resolve_policy("codex", allow_artifact, "hash", workspace=workspace_b) is None
    exact_decisions = [item for item in store.list_policy_decisions() if item["source"] == "policy-bundle"]
    assert {item["scope"] for item in exact_decisions} == {"workspace"}
    stored_workspaces = {item["workspace"] for item in exact_decisions}
    assert len(stored_workspaces) == 1
    assert next(iter(stored_workspaces)).startswith("workspace:")
    assert {item["artifact_id"] for item in exact_decisions} == {allow_artifact, block_artifact}
    assert {item["expires_at"] for item in exact_decisions} == {
        "2026-12-01T00:00:00.000000+00:00",
        "2026-10-01T00:00:00.000000+00:00",
    }
