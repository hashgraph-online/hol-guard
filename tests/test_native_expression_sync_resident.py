"""Ordinary signed sync to a real source-built resident and attributed decision.

Feature negotiation is explicitly staged over an exact verified binary. HTTP
and initial identity/anchor enrollment are synthetic. No installed release,
remote service, real tool execution, or default advertisement is certified.
"""

from __future__ import annotations

import copy
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard import native_hook_edge
from codex_plugin_scanner.guard.native_policy_snapshot import NativePolicySnapshotPublisher
from codex_plugin_scanner.guard.policy_bundle_materialization import POLICY_BUNDLE_MATERIALIZATION_KEY
from codex_plugin_scanner.guard.policy_bundle_trusted_keys import validate_synced_policy_bundle
from scripts.native_slo_session import stop_native_resident
from tests.native_expression_resident_fixtures import COMMAND
from tests.native_expression_sync_fixtures import ordinary_sync_test_status, signed_sync_fixture
from tests.native_scoped_resident_fixtures import raw_payload


def test_signed_sync_fixture_leaves_target_policy_unstaged(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fixture = signed_sync_fixture(tmp_path, monkeypatch)
    store = fixture.store
    assert store.get_sync_payload("policy_bundle") is None
    assert store.get_sync_payload("policy_bundle_ack") is None
    assert store.get_sync_payload(POLICY_BUNDLE_MATERIALIZATION_KEY) is None
    assert store.list_policy_decisions() == []
    accepted, reason, _ = validate_synced_policy_bundle(
        fixture.bundle,
        stored_keyring=store.get_sync_payload("policy_bundle_keyring"),
        expected_workspace_id=store.get_cloud_workspace_id(),
    )
    assert accepted == fixture.bundle and reason is None
    tampered = copy.deepcopy(fixture.bundle)
    tampered["payload"]["spec"]["rules"][1]["effect"] = "allow"
    rejected, reason, _ = validate_synced_policy_bundle(
        tampered,
        stored_keyring=store.get_sync_payload("policy_bundle_keyring"),
        expected_workspace_id=store.get_cloud_workspace_id(),
    )
    assert rejected is None and reason is not None


@pytest.mark.slow
def test_ordinary_signed_sync_reaches_actual_resident_and_preserves_authority_fences(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for name in ("HOL_GUARD_TEST_MODE", "HOL_GUARD_PYTHON_ORACLE", "HOL_GUARD_NATIVE_DIAGNOSTIC"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("HOL_GUARD_POLICY_CANONICAL_ENFORCEMENT", "1")
    status = ordinary_sync_test_status()
    assert status.identity is not None and status.capabilities is not None
    capabilities = status.capabilities
    # Only capability names are fixture-negotiated; executable availability,
    # compatibility, bytes, source SHA, resident transport and ACK are real.
    monkeypatch.setattr(native_hook_edge, "native_runtime_status", lambda: status)
    fixture = signed_sync_fixture(tmp_path, monkeypatch)
    store = fixture.store
    assert store.get_sync_payload("policy_bundle") is None
    assert store.get_sync_payload("policy_bundle_ack") is None
    assert store.list_policy_decisions() == []
    publisher = NativePolicySnapshotPublisher(store=store, status_provider=lambda: status)

    def require_action(expected: str = "block", rule_id: str | None = "block.expression") -> dict[str, Any]:
        edge = native_hook_edge.review_raw_hook_native(
            payload=raw_payload(COMMAND),
            harness="codex",
            event="PreToolUse",
            guard_home=store.guard_home,
            home_dir=tmp_path,
            cwd=fixture.workspace,
            source_ref_external_allowed=False,
            observe_mode=False,
            deadline=time.monotonic() + 5,
            policy_snapshot=publisher.current_snapshot_binding(),
        )
        assert edge is not None, "the real resident must return an authenticated scoped result"
        assert edge["schema"] == "guard-hook-edge-result.v3" and edge["authority"] == "rust"
        assert edge["result"]["policy_action"] == expected
        assert edge["result"]["decision"] == ("allow" if expected == "allow" else "deny")
        assert publisher.result_binding_is_current(edge["policy_binding"])
        assert edge["receipt"]["rule_digest"] == capabilities.rule_digest
        identity = publisher.policy_rule_identity_for_result(edge["policy_binding"])
        if rule_id is None:
            assert identity is None and edge["policy_binding"]["selected_decision_id"] is None
            return edge
        assert identity is not None and identity.publication is not None
        assert identity.to_dict() == {
            "policyId": "synthetic.expression-policy",
            "ruleId": rule_id,
            "policyVersion": "7",
        }
        assert identity.publication.bundle_hash == fixture.source.bundle_hash
        assert identity.publication.bundle_version == 9
        return edge

    def require_persisted_acceptance(edge: dict[str, Any]) -> None:
        record = store.get_sync_payload("native_policy_bundle_ack_acceptance")
        assert isinstance(record, dict)
        binding = record["binding"]
        assert isinstance(binding, dict) and set(binding) == {
            "generation",
            "policy_digest",
            "source_input_digest",
            "runtime_identity",
            "resident_generation",
            "mode",
        }
        assert binding == publisher.current_snapshot_binding()
        expected_result = {key: value for key, value in binding.items() if key not in {"generation", "mode"}}
        expected_result["policy_generation"] = binding["generation"]
        assert {
            key: value for key, value in edge["policy_binding"].items() if key != "selected_decision_id"
        } == expected_result
        source = record["source"]
        assert isinstance(source, dict)
        assert source["digest"] == fixture.source.bundle_hash and source["revision"] == 9
        assert source["workspace_id"] == fixture.bundle["workspaceId"]
        assert source["device_id"] == store.get_or_create_installation_id()
        assert record["ack"] == store.get_sync_payload("policy_bundle_ack")
        ack = record["ack"]
        assert isinstance(ack, dict) and isinstance(ack["observedAt"], str)
        observed = datetime.fromisoformat(ack["observedAt"].replace("Z", "+00:00"))
        assert before_sync <= observed <= datetime.now(timezone.utc)

    try:
        publisher.start()
        assert publisher.wait_until_ready(), publisher.last_error
        baseline = require_action("allow", None)
        before_sync = datetime.now(timezone.utc)
        first = fixture.sync()
        assert first["policy_validation_status"] == "accepted"
        assert first["policy_application_status"] == "applied", (first, publisher.last_error)
        assert fixture.requests and store.get_sync_payload("policy_bundle") == fixture.bundle
        acknowledgement = store.get_sync_payload("policy_bundle_ack")
        assert isinstance(acknowledgement, dict) and acknowledgement["status"] == "applied"
        assert acknowledgement["bundleHash"] == fixture.source.bundle_hash
        assert acknowledgement["bundleVersion"] == 9
        assert isinstance(store.get_sync_payload("native_policy_bundle_ack_acceptance"), dict)
        materialized = store.get_sync_payload(POLICY_BUNDLE_MATERIALIZATION_KEY)
        assert isinstance(materialized, dict)
        assert {row["owner"] for row in store.list_policy_decisions()} == {"unrelated.generic"}
        blocked = require_action()
        require_persisted_acceptance(blocked)
        assert blocked["receipt"]["policy_digest"] != baseline["receipt"]["policy_digest"]
        binding = publisher.current_snapshot_binding()
        assert binding is not None
        generation = binding["generation"]
        assert type(generation) is int
        assert (
            native_hook_edge.review_raw_hook_native(
                payload=raw_payload(COMMAND),
                harness="codex",
                event="PreToolUse",
                guard_home=store.guard_home,
                home_dir=tmp_path,
                cwd=fixture.workspace,
                source_ref_external_allowed=False,
                observe_mode=False,
                deadline=time.monotonic() + 5,
                policy_snapshot={**binding, "generation": generation + 1},
            )
            is None
        )

        # A genuinely invalid incoming candidate cannot replace the accepted
        # signed source. Ordinary sync must retain and republish that exact LKG.
        tampered = copy.deepcopy(fixture.bundle)
        tampered["payload"]["spec"]["rules"][1]["effect"] = "allow"
        fixture.response = {"policyBundle": tampered}
        rejected = fixture.sync()
        assert rejected["policy_validation_status"] == "rejected"
        assert store.get_sync_payload("policy_bundle") == fixture.bundle
        assert store.get_sync_payload("policy_bundle_ack") == acknowledgement
        assert store.get_sync_payload(POLICY_BUNDLE_MATERIALIZATION_KEY) == materialized
        before_restart = require_action()

        # Stop the actual owned resident, with the old publisher closed so it
        # cannot mask restart by racing an automatic replacement. A fresh
        # registered publisher must earn a new binding through ordinary sync.
        publisher.close()
        assert stop_native_resident(status.identity.path, store.guard_home, write_diagnostic=False).contained
        assert not publisher.result_binding_is_current(before_restart["policy_binding"])
        publisher = NativePolicySnapshotPublisher(store=store, status_provider=lambda: status)
        assert not publisher.is_ready() and publisher.current_snapshot_binding() is None
        fixture.response = {}
        recovered = fixture.sync()
        assert recovered["policy_validation_status"] == "omitted"
        assert publisher.is_ready(), (recovered, publisher.last_error)
        assert store.get_sync_payload("policy_bundle_ack") == acknowledgement
        assert store.get_sync_payload(POLICY_BUNDLE_MATERIALIZATION_KEY) == materialized
        after_restart = require_action()
        require_persisted_acceptance(after_restart)
        assert after_restart["policy_binding"] != before_restart["policy_binding"]
        assert not publisher.result_binding_is_current(before_restart["policy_binding"])

        # A trusted-anchor withdrawal is an actual authority mutation. No
        # retained applied ACK may reopen readiness or confer a current identity.
        keyring = store.get_sync_payload("policy_bundle_keyring")
        assert isinstance(keyring, dict)
        keys = keyring["keys"]
        assert isinstance(keys, list) and isinstance(keys[0], dict)
        keys[0]["state"] = "revoked"
        store.set_sync_payload("policy_bundle_keyring", keyring, datetime.now(timezone.utc).isoformat())
        # Raw fixture storage does not claim synchronous disk revocation on the
        # hook. The ordinary refresh observes it and closes publication readiness.
        withdrawn = fixture.sync()
        assert withdrawn["policy_application_status"] != "applied"
        assert not publisher.is_ready() and publisher.current_snapshot_binding() is None
        assert publisher.policy_rule_identity_for_result(after_restart["policy_binding"]) is None
    finally:
        publisher.close()
        assert stop_native_resident(status.identity.path, store.guard_home, write_diagnostic=False).contained
