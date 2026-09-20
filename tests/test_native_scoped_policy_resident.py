"""Actual resident consumption with explicit test-only staged negotiation.

This source-built component proof does not certify production advertisement,
the default route, installed wheels, or unsupported command/managed semantics.
"""

from __future__ import annotations

import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard import native_hook_edge
from codex_plugin_scanner.guard.native_policy_snapshot import NativePolicySnapshotPublisher
from scripts.native_slo_session import stop_native_resident
from tests.native_policy_receipt_resident import assert_actual_native_receipt_provenance
from tests.native_scoped_resident_fixtures import (
    COMMAND,
    HARNESS,
    explicitly_negotiated_test_status,
    prepare_store,
    publish_source,
    raw_payload,
)


@pytest.mark.slow
@pytest.mark.parametrize("source", ["canonical", "memory"])
def test_signed_exact_policy_is_consumed_by_actual_resident(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, source: str
):
    for variable in ("HOL_GUARD_TEST_MODE", "HOL_GUARD_PYTHON_ORACLE", "HOL_GUARD_NATIVE_DIAGNOSTIC"):
        monkeypatch.delenv(variable, raising=False)
    status = explicitly_negotiated_test_status()
    assert status.identity is not None and status.capabilities is not None
    # Preserve actual IPC, executable identity, rules, signatures, and matching.
    # Only the staged feature names are supplied explicitly for this test.
    monkeypatch.setattr(native_hook_edge, "native_runtime_status", lambda: status)
    store, workspace = prepare_store(tmp_path)
    publisher = NativePolicySnapshotPublisher(store=store, status_provider=lambda: status)

    def evaluate(payload: dict[str, Any] | None = None, binding: dict[str, object] | None = None):
        return native_hook_edge.review_raw_hook_native(
            payload=raw_payload() if payload is None else payload,
            harness=HARNESS,
            event="PreToolUse",
            guard_home=store.guard_home,
            home_dir=tmp_path,
            cwd=workspace,
            source_ref_external_allowed=False,
            observe_mode=False,
            deadline=time.monotonic() + 5,
            policy_snapshot=publisher.current_snapshot_binding() if binding is None else binding,
        )

    def assert_review(edge: dict[str, Any] | None):
        assert edge is not None, "the actual resident must return an authenticated scoped review"
        assert edge["schema"] == "guard-hook-edge-result.v3" and edge["authority"] == "rust"
        assert edge["result"]["decision"] == "deny" and edge["result"]["policy_action"] == "review"
        assert edge["policy_binding"]["selected_decision_id"] is None
        assert publisher.result_binding_is_current(edge["policy_binding"])

    try:
        publisher._publish_once()
        assert publisher.is_ready(), publisher.last_error
        before = evaluate()
        assert before is not None
        # Advertised capabilities do not create scoped authority. The empty
        # baseline uses authenticated defaults until a signed source requires
        # the scoped publication contract.
        assert before["schema"] == "guard-hook-edge-result.v2" and before["authority"] == "rust"
        assert before["result"]["decision"] == "deny" and before["result"]["policy_action"] == "review"
        baseline_binding = publisher.current_snapshot_binding()
        assert baseline_binding is not None and "source_input_digest" not in baseline_binding
        assert before["receipt"]["policy_generation"] == baseline_binding["generation"]
        assert before["receipt"]["policy_digest"] == baseline_binding["policy_digest"]
        assert before["receipt"]["runtime_identity"] == baseline_binding["runtime_identity"]
        publish_source(store, source)
        assert not publisher.is_ready()
        assert publisher.current_snapshot_binding() is None
        publisher._publish_once()
        assert publisher.is_ready(), publisher.last_error
        after = evaluate()  # First action after real signed publication and ACK.
        assert after is not None
        assert after["schema"] == "guard-hook-edge-result.v3" and after["authority"] == "rust"
        assert after["result"]["decision"] == "allow" and after["result"]["policy_action"] == "allow"
        assert after["policy_binding"]["selected_decision_id"] is not None
        assert publisher.result_binding_is_current(after["policy_binding"])
        assert after["receipt"]["policy_digest"] != before["receipt"]["policy_digest"]
        assert after["receipt"]["rule_digest"] == status.capabilities.rule_digest
        identity = publisher.policy_rule_identity_for_result(after["policy_binding"])
        if source == "canonical":
            assert identity is not None and identity.to_dict() == {
                "policyId": "synthetic-policy",
                "ruleId": "synthetic-rule",
                "policyVersion": "8",
            }
        else:
            assert identity is None

        durable_context = None
        if source == "canonical":
            durable_context = assert_actual_native_receipt_provenance(store, publisher, tmp_path, workspace)

        for command in (COMMAND.strip(), COMMAND.replace("  ", " "), COMMAND.replace("Synthetic", "synthetic")):
            assert_review(evaluate(raw_payload(command)))
        assert_review(evaluate({**raw_payload(), "artifact_id": "codex:project:unrelated"}))
        assert_review(evaluate({**raw_payload(), "tool_name": "Shell"}))
        ambiguous = {**raw_payload(), "tool_input": {"command": COMMAND, "cmd": COMMAND}}
        assert evaluate(ambiguous) is None
        binding = publisher.current_snapshot_binding()
        assert binding is not None
        generation = binding["generation"]
        assert isinstance(generation, int)
        assert evaluate(binding={**binding, "source_input_digest": "0" * 64}) is None
        assert evaluate(binding={**binding, "generation": generation + 1}) is None

        # Real authority withdrawal invalidates even a previously valid reply.
        if source == "memory":
            store.clear_review_policy_memory_state()
        else:
            keyring = store.get_sync_payload("policy_bundle_keyring")
            assert isinstance(keyring, dict)
            keys = keyring["keys"]
            assert isinstance(keys, list) and isinstance(keys[0], dict)
            keys[0]["state"] = "revoked"
            store.set_sync_payload("policy_bundle_keyring", keyring, datetime.now(timezone.utc).isoformat())
            publisher.request_publish()
        assert not publisher.result_binding_is_current(after["policy_binding"])
        if durable_context is not None:
            receipt_id, original_context = durable_context
            stored = store.get_receipt(receipt_id)
            assert stored is not None
            assert stored["action_envelope_json"]["nativePolicyDecision"] == original_context
            assert stored["timestamp"] == original_context["recordedAt"]
        publisher._publish_once()
        if source == "canonical":
            assert not publisher.is_ready()
            assert publisher.last_error == "native_policy_authority_bundle_unavailable"
        else:
            assert publisher.is_ready(), publisher.last_error
            assert_review(evaluate())
    finally:
        publisher.close()
        assert stop_native_resident(status.identity.path, store.guard_home, write_diagnostic=False).contained
