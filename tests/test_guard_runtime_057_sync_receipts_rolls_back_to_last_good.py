"""Runtime regression tests: sync receipts rolls back to last good."""

from __future__ import annotations

from tests.guard_runtime_test_dependencies import (
    GuardArtifact,
    GuardConfig,
    GuardStore,
    HarnessDetection,
    evaluate_detection,
    guard_runner_module,
    json,
    policy_bundle_test_keyring,
    stub_authenticated_urlopen,
)
from tests.guard_runtime_test_support import (
    _cache_signed_test_policy_bundle,
    _seed_guard_cloud,
    _signed_test_policy_bundle,
)
from tests.guard_runtime_test_support import (
    _isolate_codex_runtime_marker as _isolate_codex_runtime_marker,
)


def test_sync_receipts_rolls_back_to_last_good_bundle_on_canonical_compile_failure(
    tmp_path,
    monkeypatch,
):
    store = GuardStore(tmp_path / "guard-home")
    _seed_guard_cloud(store, workspace_id="workspace-1")
    monkeypatch.setenv("HOL_GUARD_POLICY_CANONICAL_ENFORCEMENT", "1")
    last_good = _signed_test_policy_bundle(
        [
            {
                "ruleId": "legacy-last-good",
                "action": "block",
                "artifactId": "command:npm-test",
                "scope": {"harnesses": ["codex"], "devices": []},
            }
        ],
        bundle_version="policy-2026-06-05.4",
        issued_at="2026-06-05T13:29:00+00:00",
    )
    store.set_sync_payload(
        "policy_bundle_keyring",
        policy_bundle_test_keyring(workspace_id="workspace-1"),
        "2026-06-05T13:29:00+00:00",
    )
    store.set_sync_payload("policy_bundle", last_good, "2026-06-05T13:29:00+00:00")
    store.set_sync_payload("policy_bundle_last_good", last_good, "2026-06-05T13:29:00+00:00")
    candidate = {
        "contractVersion": "guard-policy-bundle.v2",
        "bundleVersion": 5,
        "bundleHash": "sha256:candidate",
        "issuedAt": "2026-06-05T13:30:00+00:00",
        "workspaceId": "workspace-1",
        "payload": {
            "apiVersion": "guard.hashgraphonline.com/v1alpha1",
            "kind": "GuardPolicy",
            "metadata": {
                "id": "policy.unsupported",
                "name": "Unsupported policy",
                "revision": 1,
            },
            "spec": {
                "defaults": {"mode": "prompt", "defaultAction": "warn"},
                "rules": [
                    {
                        "id": "rule.unsupported-operation",
                        "enabled": True,
                        "effect": "block",
                        "match": {"operations": ["browser.navigate"]},
                        "lifetime": {"mode": "permanent", "expiresAt": None},
                        "provenance": {
                            "source": "manual",
                            "receiptIds": [],
                            "createdAt": "2026-06-05T13:30:00Z",
                            "createdBy": "owner-1",
                        },
                    }
                ],
            },
        },
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
        return _Response(
            {
                "syncedAt": "2026-06-05T13:30:01+00:00",
                "receiptsStored": 0,
                "policyBundle": candidate,
            }
        )

    stub_authenticated_urlopen(monkeypatch, _fake_urlopen)
    monkeypatch.setattr(
        guard_runner_module,
        "validate_synced_policy_bundle",
        lambda policy_bundle, *args, **kwargs: (policy_bundle, None, ()),
    )
    monkeypatch.setattr(
        guard_runner_module,
        "_validate_cached_policy_bundle",
        lambda _store, policy_bundle: (
            policy_bundle if isinstance(policy_bundle, dict) else None,
            None,
        ),
    )
    monkeypatch.setattr(
        guard_runner_module,
        "sync_pain_signals",
        lambda _store, auth_context=None: 0,
    )

    guard_runner_module.sync_receipts(store)

    assert store.get_sync_payload("policy_bundle") == last_good
    assert store.get_sync_payload("policy_bundle_last_good") == last_good
    assert store.get_sync_payload("policy_bundle_last_error") == {
        "reason": "canonical_compile_unsupported_policy_match"
    }
    assert [decision["owner"] for decision in store.list_policy_decisions()] == ["legacy-last-good"]
    rollback_events = store.list_events(event_name="policy_bundle/rollback")
    assert rollback_events[-1]["payload"] == {
        "reason": "canonical_compile_unsupported_policy_match",
        "restored": "policy_bundle_last_good",
    }


def test_sync_receipts_keeps_legacy_bundle_active_on_canonical_shadow_mismatch(
    tmp_path,
    monkeypatch,
):
    store = GuardStore(tmp_path / "guard-home")
    _seed_guard_cloud(store, workspace_id="workspace-1")
    monkeypatch.setenv("HOL_GUARD_POLICY_CANONICAL_ENFORCEMENT", "1")
    legacy = _signed_test_policy_bundle(
        [
            {
                "ruleId": "legacy-rule",
                "action": "block",
                "artifactId": "skill:hol/deploy",
                "scope": {"harnesses": ["codex"], "devices": []},
            }
        ],
        bundle_version="policy-2026-06-05.4",
        issued_at="2026-06-05T13:29:00+00:00",
    )
    store.set_sync_payload(
        "policy_bundle_keyring",
        policy_bundle_test_keyring(workspace_id="workspace-1"),
        "2026-06-05T13:29:00+00:00",
    )
    store.set_sync_payload("policy_bundle", legacy, "2026-06-05T13:29:00+00:00")
    store.set_sync_payload("policy_bundle_legacy_last_good", legacy, "2026-06-05T13:29:00+00:00")
    candidate = {
        "contractVersion": "guard-policy-bundle.v2",
        "bundleVersion": 5,
        "bundleHash": "a" * 64,
        "issuedAt": "2026-06-05T13:30:00Z",
        "workspaceId": "workspace-1",
        "payload": {
            "apiVersion": "guard.hashgraphonline.com/v1alpha1",
            "kind": "GuardPolicy",
            "metadata": {
                "id": "policy.shadow-mismatch",
                "name": "Shadow mismatch",
                "revision": 1,
            },
            "spec": {
                "defaults": {"mode": "prompt", "defaultAction": "warn"},
                "rules": [
                    {
                        "id": "rule.canonical",
                        "enabled": True,
                        "effect": "allow",
                        "match": {
                            "artifacts": ["skill:hol/deploy"],
                            "harnesses": ["codex"],
                        },
                        "lifetime": {"mode": "permanent", "expiresAt": None},
                        "provenance": {
                            "source": "manual",
                            "receiptIds": [],
                            "createdAt": "2026-06-05T13:30:00Z",
                            "createdBy": "owner-1",
                        },
                    }
                ],
            },
        },
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
        return _Response(
            {
                "syncedAt": "2026-06-05T13:30:01+00:00",
                "receiptsStored": 0,
                "policyBundle": candidate,
            }
        )

    stub_authenticated_urlopen(monkeypatch, _fake_urlopen)
    monkeypatch.setattr(
        guard_runner_module,
        "validate_synced_policy_bundle",
        lambda policy_bundle, *args, **kwargs: (policy_bundle, None, ()),
    )
    monkeypatch.setattr(
        guard_runner_module,
        "_validate_cached_policy_bundle",
        lambda _store, policy_bundle: (
            policy_bundle if isinstance(policy_bundle, dict) else None,
            None,
        ),
    )
    monkeypatch.setattr(
        guard_runner_module,
        "sync_pain_signals",
        lambda _store, auth_context=None: 0,
    )

    guard_runner_module.sync_receipts(store)

    assert store.get_sync_payload("policy_bundle") == legacy
    assert store.get_sync_payload("policy_bundle_canonical_last_good") is None
    assert store.get_sync_payload("policy_bundle_last_error") == {"reason": "canonical_shadow_mismatch"}
    assert [decision["action"] for decision in store.list_policy_decisions()] == ["block"]
    mismatch_events = store.list_events(event_name="policy_bundle/shadow_mismatch")
    assert mismatch_events[-1]["payload"] == {
        "canonicalRows": 1,
        "legacyRows": 1,
        "reasonCodes": ["action"],
        "status": "mismatch",
    }


def test_sync_receipts_clears_untrusted_cached_canonical_when_flag_is_disabled(
    tmp_path,
    monkeypatch,
):
    store = GuardStore(tmp_path / "guard-home")
    _seed_guard_cloud(store, workspace_id="workspace-a")
    monkeypatch.delenv("HOL_GUARD_POLICY_CANONICAL_ENFORCEMENT", raising=False)
    canonical_bundle = {
        "contractVersion": "guard-policy-bundle.v2",
        "bundleVersion": 5,
        "bundleHash": "sha256:canonical",
        "issuedAt": "2026-06-05T13:30:00+00:00",
        "workspaceId": "workspace-a",
        "payload": {
            "apiVersion": "guard.hashgraphonline.com/v1alpha1",
            "kind": "GuardPolicy",
            "metadata": {
                "id": "policy.canonical",
                "name": "Canonical policy",
                "revision": 5,
            },
            "spec": {"defaults": {"mode": "prompt", "defaultAction": "warn"}, "rules": []},
        },
    }
    legacy_bundle = {
        "contractVersion": "guard-policy-bundle.v1",
        "bundleVersion": "policy-2026-06-05.4",
        "bundleHash": "sha256:legacy",
        "issuedAt": "2026-06-05T13:29:00+00:00",
        "rules": [
            {
                "ruleId": "legacy-last-good",
                "action": "block",
                "artifactId": "command:npm-test",
                "scope": {"harnesses": ["codex"], "devices": []},
            }
        ],
    }
    store.set_sync_payload("policy_bundle", canonical_bundle, "2026-06-05T13:30:00+00:00")
    store.set_sync_payload(
        "policy_bundle_canonical_last_good",
        canonical_bundle,
        "2026-06-05T13:30:00+00:00",
    )
    store.set_sync_payload(
        "policy_bundle_legacy_last_good",
        legacy_bundle,
        "2026-06-05T13:29:00+00:00",
    )

    class _Response:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def read(self) -> bytes:
            return json.dumps(
                {
                    "syncedAt": "2026-06-05T13:31:00+00:00",
                    "receiptsStored": 0,
                }
            ).encode("utf-8")

    def _fake_urlopen(request, timeout):
        return _Response()

    stub_authenticated_urlopen(monkeypatch, _fake_urlopen)
    monkeypatch.setattr(
        guard_runner_module,
        "sync_pain_signals",
        lambda _store, auth_context=None: 0,
    )

    guard_runner_module.sync_receipts(store)

    assert store.get_sync_payload("policy_bundle") is None
    assert store.list_policy_decisions() == []
    last_error = store.get_sync_payload("policy_bundle_last_error")
    assert isinstance(last_error, dict)
    assert last_error["reason"] == "missing_required_field"


def test_policy_bundle_decision_resolves_before_receipt_persistence(tmp_path, monkeypatch):
    guard_home = tmp_path / "guard-home"
    workspace = tmp_path / "workspace"
    store = GuardStore(guard_home)
    bundle = {
        "bundleVersion": "policy-2026-06-05.2",
        "expiresAt": None,
        "rules": [
            {
                "ruleId": "pkg-block",
                "action": "block",
                "reason": "Block risky package installs before execution.",
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
        ],
    }
    store.replace_remote_policies(
        guard_runner_module._build_policy_bundle_decisions(
            bundle,
            device_id=guard_runner_module._guard_device_metadata(store)[0],
            device_name="MacBook Pro",
        ),
        "2026-06-05T13:31:00+00:00",
        remote_write_authorized=True,
    )
    _cache_signed_test_policy_bundle(store, bundle["rules"])

    order: list[str] = []
    original_resolve_policy = store.resolve_policy_decision_lookup_with_memory_pattern
    original_add_receipt = store.add_receipt

    def tracked_resolve_policy(*args, **kwargs):
        assert kwargs.get("consume_one_shot") is False
        order.append("resolve_policy_non_consuming")
        return original_resolve_policy(*args, **kwargs)

    def tracked_add_receipt(receipt):
        order.append("add_receipt")
        return original_add_receipt(receipt)

    monkeypatch.setattr(store, "resolve_policy_decision_lookup_with_memory_pattern", tracked_resolve_policy)
    monkeypatch.setattr(store, "add_receipt", tracked_add_receipt)

    detection = HarnessDetection(
        harness="codex",
        installed=True,
        command_available=True,
        config_paths=(str(workspace / "opencode.json"),),
        artifacts=(
            GuardArtifact(
                artifact_id="codex:project:package-request:proof",
                name="npm install proof",
                harness="codex",
                artifact_type="package_request",
                source_scope="project",
                config_path=str(workspace / "opencode.json"),
                metadata={"package_manager": "npm"},
            ),
        ),
    )
    config = GuardConfig(guard_home=guard_home, workspace=workspace, mode="enforce")

    result = evaluate_detection(detection, store, config, persist=True)

    assert result["artifacts"][0]["policy_action"] == "block"
    assert order.index("resolve_policy_non_consuming") < order.index("add_receipt")
