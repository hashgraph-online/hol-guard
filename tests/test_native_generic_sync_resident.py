"""Ordinary signed generic sync earns application from the actual auto resident.

HTTP and enrollment are synthetic; capability names and canonical enforcement
are explicitly staged for this component proof. No installed channel or default
rollout is certified. Policy, publication, native transport and ACK are real.
"""

from __future__ import annotations

import copy
import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from codex_plugin_scanner.guard import native_hook_edge
from codex_plugin_scanner.guard.config import load_guard_config
from codex_plugin_scanner.guard.native_policy_snapshot import NativePolicySnapshotPublisher
from codex_plugin_scanner.guard.policy_bundle_materialization import POLICY_BUNDLE_MATERIALIZATION_KEY
from codex_plugin_scanner.guard.policy_bundle_trusted_keys import validate_synced_policy_bundle
from codex_plugin_scanner.guard.runtime import runner
from codex_plugin_scanner.guard.runtime.policy_runtime_posture import local_policy_runtime_posture
from scripts.native_slo_session import stop_native_resident
from tests.native_sensitive_resident_fixtures import sensitive_test_status
from tests.support.network import stub_authenticated_urlopen
from tests.test_policy_bundle_v2 import _signed_bundle, _verification_key
from tests.test_policy_bundle_v2_runtime_admission import (
    _generic_v2_payload,
    _seed_v2_admission_store,
    _SyncResponse,
)


def _source(tmp_path: Path, shape: str, *, mode: str = "enforce"):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    verification = _verification_key(key, workspace_id="workspace-alpha")
    payload: dict[str, Any] = _generic_v2_payload(rule_id="synthetic.block", artifact_id="codex:project:Shell")
    payload["spec"]["defaults"] = {"mode": mode, "defaultAction": "allow"}
    if shape == "defaults":
        payload["spec"]["rules"] = []
        payload["spec"]["defaults"]["defaultAction"] = "block"
    else:
        assert shape == "scoped"
    bundle = _signed_bundle(key, verification, payload_base=payload)
    store = _seed_v2_admission_store(tmp_path, verification)
    (store.guard_home / "config.toml").write_text(f'mode="{mode}"\ndefault_action="allow"\n')
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    return store, workspace, bundle


def test_generic_sync_source_is_signed_and_target_authority_is_unstaged(tmp_path: Path) -> None:
    for shape, mode in (("defaults", "enforce"), ("scoped", "enforce"), ("defaults", "observe")):
        store, _, bundle = _source(tmp_path / f"{shape}-{mode}", shape, mode=mode)
        assert store.get_sync_payload("policy_bundle") is None
        assert store.get_sync_payload("policy_bundle_ack") is None
        assert store.get_sync_payload(POLICY_BUNDLE_MATERIALIZATION_KEY) is None
        assert store.list_policy_decisions() == []
        config = load_guard_config(store.guard_home)
        assert config.default_action == "allow" and config.subprocess_action == "warn"
        accepted, reason, _ = validate_synced_policy_bundle(
            bundle,
            stored_keyring=store.get_sync_payload("policy_bundle_keyring"),
            expected_workspace_id=store.get_cloud_workspace_id(),
        )
        assert accepted == bundle and reason is None


@pytest.mark.slow
@pytest.mark.parametrize("shape", ["defaults", "scoped"])
def test_ordinary_generic_sync_requires_actual_auto_resident_acceptance(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, shape: str
) -> None:
    for name in ("HOL_GUARD_TEST_MODE", "HOL_GUARD_PYTHON_ORACLE", "HOL_GUARD_NATIVE_DIAGNOSTIC"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("HOL_GUARD_POLICY_CANONICAL_ENFORCEMENT", "1")
    status = sensitive_test_status()
    assert status.identity is not None and status.capabilities is not None
    monkeypatch.setattr(native_hook_edge, "native_runtime_status", lambda: status)
    store, workspace, bundle = _source(tmp_path, shape)
    publisher = NativePolicySnapshotPublisher(store=store, status_provider=lambda: status)
    requests: list[dict[str, Any]] = []
    response: dict[str, object] = {"policyBundle": bundle}

    def exchange(request: Any, timeout: object = None) -> _SyncResponse:
        if request.full_url.endswith("/api/guard/receipts/sync"):
            requests.append(json.loads(request.data))
            return _SyncResponse({"syncedAt": datetime.now(timezone.utc).isoformat(), "receiptsStored": 0, **response})
        return _SyncResponse({"accepted": 0, "rejected": 0, "statuses": []})

    stub_authenticated_urlopen(monkeypatch, exchange)

    def sync() -> dict[str, object]:
        return runner.sync_receipts(
            store,
            auth_context={
                "sync_url": "https://hol.org/api/guard/receipts/sync",
                "access_token": "synthetic-test-token",
                "dpop_key_material": None,
            },
        )

    def edge(expected: str, *, scoped: bool = True) -> dict[str, Any]:
        binding = publisher.current_snapshot_binding()
        assert binding is not None
        result = native_hook_edge.review_raw_hook_native(
            payload={"tool_name": "Shell", "tool_input": {"command": "printf synthetic"}},
            harness="codex",
            event="PreToolUse",
            guard_home=store.guard_home,
            home_dir=tmp_path,
            cwd=workspace,
            source_ref_external_allowed=False,
            observe_mode=False,
            deadline=time.monotonic() + 5,
            policy_snapshot=binding,
        )
        assert result is not None, f"{shape}: actual authenticated resident response required"
        assert result["authority"] == "rust" and result["result"]["policy_action"] == expected
        assert result["result"]["decision"] == ("deny" if expected == "block" else "allow")
        if scoped:
            assert result["schema"] == "guard-hook-edge-result.v3"
            assert publisher.result_binding_is_current(result["policy_binding"])
        else:
            assert result["schema"] == "guard-hook-edge-result.v2" and "policy_binding" not in result
            assert not publisher.requires_scoped_authority
            assert "source_input_digest" not in binding
            assert publisher.current_snapshot_binding() == binding
        assert result["receipt"]["policy_generation"] == binding["generation"]
        assert result["receipt"]["policy_digest"] == binding["policy_digest"]
        assert result["receipt"]["runtime_identity"] == binding["runtime_identity"]
        assert result["receipt"]["policy_action"] == expected
        return result

    try:
        publisher.start()
        assert publisher.wait_until_ready(), publisher.last_error
        baseline = edge("warn", scoped=False)
        assert store.get_sync_payload("policy_bundle_ack") is None
        first = sync()
        assert first["policy_validation_status"] == "accepted", first
        assert first["policy_application_status"] == "applied", (first, publisher.last_error)
        assert store.get_sync_payload("policy_bundle") == bundle
        ack = store.get_sync_payload("policy_bundle_ack")
        assert isinstance(ack, dict) and ack["status"] == "applied"
        assert ack["bundleHash"] == bundle["bundleHash"] and ack["bundleVersion"] == bundle["bundleVersion"]
        evidence = store.get_sync_payload("native_policy_bundle_ack_acceptance")
        assert isinstance(evidence, dict) and evidence["ack"] == ack
        assert evidence["binding"] == publisher.current_snapshot_binding()
        current = local_policy_runtime_posture(store, device_id=store.get_or_create_installation_id())
        assert current["selected_enforcement_lane"] == "canonical"
        assert current["canonical_policy_application_status"] == "current"
        assert current["canonical_policy_application_mode"] == "enforce"
        assert isinstance(store.get_sync_payload(POLICY_BUNDLE_MATERIALIZATION_KEY), dict)
        blocked = edge("block")
        assert blocked["receipt"]["policy_digest"] != baseline["receipt"]["policy_digest"]
        assert (blocked["policy_binding"]["selected_decision_id"] is None) is (shape == "defaults")
        identity = publisher.policy_rule_identity_for_result(blocked["policy_binding"])
        if shape == "defaults":
            assert identity is None
        else:
            assert identity is not None and identity.publication is not None
            assert identity.to_dict() == {
                "policyId": "policy.runtime-admission",
                "ruleId": "synthetic.block",
                "policyVersion": "1",
            }
            assert identity.publication.bundle_hash == bundle["bundleHash"]
        response.clear()
        second = sync()
        assert second["policy_validation_status"] == "omitted", second
        assert second["policy_application_status"] == "retained", second
        assert len(requests) == 2 and requests[1]["syncContext"]["policyBundleAcknowledgementV2"] == ack
        assert store.get_sync_payload("policy_bundle_ack") == ack
        retained_evidence = store.get_sync_payload("native_policy_bundle_ack_acceptance")
        assert isinstance(retained_evidence, dict) and retained_evidence["ack"] == ack
        assert retained_evidence["binding"] == publisher.current_snapshot_binding()
        edge("block")
        tampered = copy.deepcopy(bundle)
        payload = tampered["payload"]
        assert isinstance(payload, dict)
        payload["spec"]["defaults"]["defaultAction"] = "review"
        response["policyBundle"] = tampered
        rejected = sync()
        assert rejected["policy_validation_status"] == "rejected"
        assert store.get_sync_payload("policy_bundle") == bundle
        assert store.get_sync_payload("policy_bundle_ack") == ack
        prior = edge("block")
        monkeypatch.setenv("HOL_GUARD_POLICY_CANONICAL_ENFORCEMENT", "0")
        response.clear()
        withdrawn = sync()
        assert withdrawn["policy_application_status"] != "applied"
        assert not publisher.result_binding_is_current(prior["policy_binding"])
        current = local_policy_runtime_posture(store, device_id=store.get_or_create_installation_id())
        assert current["selected_enforcement_lane"] == "unverified"
        assert current["canonical_incompatibility_reason"] == "canonical_enforcement_disabled"
    finally:
        publisher.close()
        assert stop_native_resident(status.identity.path, store.guard_home, write_diagnostic=False).contained


@pytest.mark.slow
@pytest.mark.parametrize("mode", ["enforce", "observe"])
def test_signed_defaults_preserve_both_hook_events_in_actual_auto_resident(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mode: str
) -> None:
    for name in ("HOL_GUARD_TEST_MODE", "HOL_GUARD_PYTHON_ORACLE", "HOL_GUARD_NATIVE_DIAGNOSTIC"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("HOL_GUARD_POLICY_CANONICAL_ENFORCEMENT", "1")
    status = sensitive_test_status()
    assert status.identity is not None and status.capabilities is not None
    rule_digest = status.capabilities.rule_digest
    monkeypatch.setattr(native_hook_edge, "native_runtime_status", lambda: status)
    store, workspace, bundle = _source(tmp_path, "defaults", mode=mode)
    publisher = NativePolicySnapshotPublisher(store=store, status_provider=lambda: status)
    requests: list[dict[str, Any]] = []
    response: dict[str, object] = {"policyBundle": bundle}

    def exchange(request: Any, timeout: object = None) -> _SyncResponse:
        if request.full_url.endswith("/api/guard/receipts/sync"):
            requests.append(json.loads(request.data))
            return _SyncResponse({"syncedAt": datetime.now(timezone.utc).isoformat(), "receiptsStored": 0, **response})
        return _SyncResponse({"accepted": 0, "rejected": 0, "statuses": []})

    stub_authenticated_urlopen(monkeypatch, exchange)

    def sync() -> dict[str, object]:
        return runner.sync_receipts(
            store,
            auth_context={
                "sync_url": "https://hol.org/api/guard/receipts/sync",
                "access_token": "synthetic-test-token",
                "dpop_key_material": None,
            },
        )

    def edge(event: str, payload: dict[str, object], *, scoped: bool = True) -> dict[str, Any]:
        binding = publisher.current_snapshot_binding()
        assert binding is not None
        result = native_hook_edge.review_raw_hook_native(
            payload=payload,
            harness="codex",
            event=event,
            guard_home=store.guard_home,
            home_dir=tmp_path,
            cwd=workspace,
            source_ref_external_allowed=False,
            observe_mode=mode == "observe",
            deadline=time.monotonic() + 5,
            policy_snapshot=binding,
        )
        assert result is not None, f"defaults-{mode}-{event}: actual resident response required"
        assert result["authority"] == "rust" and result["event_name"] == event
        assert result["receipt"]["policy_generation"] == binding["generation"]
        assert result["receipt"]["policy_digest"] == binding["policy_digest"]
        assert result["receipt"]["runtime_identity"] == binding["runtime_identity"]
        assert result["receipt"]["rule_digest"] == rule_digest
        if scoped:
            assert result["schema"] == "guard-hook-edge-result.v3"
            assert publisher.result_binding_is_current(result["policy_binding"])
            assert result["policy_binding"]["selected_decision_id"] is None
            assert result["receipt"]["observe_mode"] is (mode == "observe")
        else:
            assert result["schema"] == "guard-hook-edge-result.v2" and "policy_binding" not in result
            assert not publisher.requires_scoped_authority
            assert "source_input_digest" not in binding
            assert publisher.current_snapshot_binding() == binding
        return result

    compound: dict[str, object] = {
        "tool_name": "Shell",
        "tool_input": {"command": "printf first && printf second"},
        "tool_response": "synthetic",
    }
    try:
        publisher.start()
        assert publisher.wait_until_ready(), publisher.last_error
        for event in ("PreToolUse", "PostToolUse"):
            baseline = edge(event, compound, scoped=False)
            assert baseline["result"]["decision"] == "allow"
        assert store.get_sync_payload("policy_bundle_ack") is None
        first = sync()
        assert first["policy_validation_status"] == "accepted", first
        assert first["policy_application_status"] == "applied", (first, publisher.last_error)
        ack = store.get_sync_payload("policy_bundle_ack")
        assert isinstance(ack, dict) and ack["status"] == "applied"
        assert ack["bundleHash"] == bundle["bundleHash"] and ack["bundleVersion"] == bundle["bundleVersion"]
        acceptance = store.get_sync_payload("native_policy_bundle_ack_acceptance")
        assert isinstance(acceptance, dict) and acceptance["ack"] == ack
        assert acceptance["binding"] == publisher.current_snapshot_binding()
        current = local_policy_runtime_posture(store, device_id=store.get_or_create_installation_id())
        assert current["selected_enforcement_lane"] == "canonical"
        assert current["canonical_policy_application_status"] == "current"
        assert current["canonical_policy_application_mode"] == mode
        for event in ("PreToolUse", "PostToolUse"):
            actual = edge(event, compound)
            assert actual["result"]["decision"] == ("allow" if mode == "observe" else "deny")
            action = "warn" if event == "PreToolUse" and mode == "observe" else "block"
            assert actual["result"]["policy_action"] == actual["receipt"]["policy_action"] == action
            assert actual["observed_policy_action"] == ("block" if mode == "observe" else None)
            if event == "PostToolUse":
                assert actual["result"]["model_output_action"] == ("allow_original" if mode == "observe" else "block")
        intrinsic = edge("PreToolUse", {"tool_name": "Shell", "tool_input": {"command": "rm -rf /"}})
        assert intrinsic["result"]["policy_action"] == "block" and intrinsic["result"]["decision"] == "deny"
        source_denial = edge(
            "PostToolUse",
            {
                "tool_name": "Read",
                "guard_source_ref": {
                    "version": 1,
                    "path": str(workspace / "missing.rs"),
                    "output_sha256": "a" * 64,
                    "output_chars": 9,
                },
            },
        )
        assert source_denial["result"]["decision"] == "deny"
        assert source_denial["result"]["model_output_action"] == "block"
        response.clear()
        second = sync()
        assert second["policy_application_status"] == "retained", second
        assert len(requests) == 2 and requests[1]["syncContext"]["policyBundleAcknowledgementV2"] == ack
        assert store.get_sync_payload("policy_bundle_ack") == ack
        keyring = store.get_sync_payload("policy_bundle_keyring")
        assert isinstance(keyring, dict)
        keys = keyring["keys"]
        assert isinstance(keys, list) and isinstance(keys[0], dict)
        keys[0]["state"] = "revoked"
        store.set_sync_payload("policy_bundle_keyring", keyring, datetime.now(timezone.utc).isoformat())
        publisher.request_publish()
        publisher._publish_once()
        assert not publisher.is_ready() and publisher.current_snapshot_binding() is None
        assert not publisher.result_binding_is_current(source_denial["policy_binding"])
        current = local_policy_runtime_posture(store, device_id=store.get_or_create_installation_id())
        assert current["selected_enforcement_lane"] != "canonical"
        assert current.get("canonical_policy_application_status") != "current"
    finally:
        publisher.close()
        assert stop_native_resident(status.identity.path, store.guard_home, write_diagnostic=False).contained
