"""Real resident expression proof with explicitly staged source admission.

The executable, signatures, ACK, source fences, expression matcher and
provenance are real. Capability negotiation is fixture-only; no installed,
ordinary-sync, browser, tool-execution or broad runtime acceptance is claimed.
"""

from __future__ import annotations

import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard import native_hook_edge
from codex_plugin_scanner.guard.config import load_guard_config
from codex_plugin_scanner.guard.native_policy_authority_contract import (
    NATIVE_SCOPED_AUTHORITY_FEATURE,
    NativePolicyAuthorityCapabilities,
)
from codex_plugin_scanner.guard.native_policy_authority_read import read_native_policy_authority_inputs
from codex_plugin_scanner.guard.native_policy_snapshot import NativePolicySnapshotPublisher
from codex_plugin_scanner.guard.native_policy_snapshot_constants import NativePolicySnapshotError
from codex_plugin_scanner.guard.native_policy_snapshot_policy import effective_native_policy_v3
from scripts.native_slo_session import stop_native_resident
from tests.native_expression_resident_fixtures import (
    ARTIFACT,
    COMMAND,
    EXACT_COMMAND,
    ExpressionSource,
    configure_expression_fixture_policy,
    expression_test_status,
    prepare_expression_store,
    publish_expression_source,
)
from tests.native_scoped_resident_fixtures import raw_payload


def test_expression_resident_baseline_config_is_explicit_and_retains_risk_floors(tmp_path: Path) -> None:
    store, _ = prepare_expression_store(tmp_path)
    loaded = load_guard_config(store.guard_home)
    policy = effective_native_policy_v3(loaded)
    defaults = effective_native_policy_v3(load_guard_config(tmp_path / "unconfigured"))
    assert loaded.mode == "enforce"
    assert policy["default_action"] == "allow"
    assert policy["harness_actions"] == {"codex": "allow"}
    assert policy["unknown_publisher_action"] == "allow"
    assert policy["subprocess_action"] == "allow"
    for key in (
        "risk_actions",
        "changed_hash_action",
        "new_network_domain_action",
        "sandbox_analysis",
        "protection_posture",
    ):
        assert policy[key] == defaults[key]
    assert policy["changed_hash_action"] == "require-reapproval"
    risks = policy["risk_actions"]
    assert isinstance(risks, dict)
    assert risks["guard_bypass"] == "block"
    assert risks["local_secret_read"] == "require-reapproval"


def test_expression_resident_source_preflight_is_signed_complete_and_expiry_bound(tmp_path: Path) -> None:
    store, workspace = prepare_expression_store(tmp_path)
    source = publish_expression_source(store, workspace, block_lifetime_seconds=60)
    captured = read_native_policy_authority_inputs(store, now=time.time())
    assert len(captured.authority.command_expressions) == 2
    assert captured.expires_at_ms == int(source.block_expires_at.timestamp() * 1000)
    with pytest.raises(NativePolicySnapshotError, match="capability_unsupported"):
        captured.authority.for_snapshot(
            NativePolicyAuthorityCapabilities(4, frozenset({NATIVE_SCOPED_AUTHORITY_FEATURE}))
        )
    expired = read_native_policy_authority_inputs(store, now=source.block_expires_at.timestamp() + 0.01)
    assert len(expired.authority.command_expressions) == 1
    assert {identity.rule_id for _, identity in expired.rule_identities} == {
        "unrelated.generic",
        "review.exact-expression",
    }
    assert expired.input_digest != captured.input_digest


@pytest.mark.slow
def test_signed_command_expressions_are_consumed_by_actual_resident(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    for name in ("HOL_GUARD_TEST_MODE", "HOL_GUARD_PYTHON_ORACLE", "HOL_GUARD_NATIVE_DIAGNOSTIC"):
        monkeypatch.delenv(name, raising=False)
    status = expression_test_status()
    assert status.identity is not None and status.capabilities is not None
    capabilities = status.capabilities
    source: ExpressionSource | None = None
    monkeypatch.setattr(native_hook_edge, "native_runtime_status", lambda: status)
    store, workspace = prepare_expression_store(tmp_path)
    # Prove the real configured Review floor first. A later explicit fixture
    # configuration must produce Allow before any signed expression is added.
    configure_expression_fixture_policy(store, unknown_publisher_action="review")
    other_workspace = tmp_path / "other-workspace"
    other_workspace.mkdir()
    publisher = NativePolicySnapshotPublisher(store=store, status_provider=lambda: status)

    def evaluate(
        command: str = COMMAND,
        *,
        payload: dict[str, object] | None = None,
        harness: str = "codex",
        cwd: Path = workspace,
        binding: dict[str, object] | None = None,
    ) -> dict[str, Any] | None:
        return native_hook_edge.review_raw_hook_native(
            payload=raw_payload(command) if payload is None else payload,
            harness=harness,
            event="PreToolUse",
            guard_home=store.guard_home,
            home_dir=tmp_path,
            cwd=cwd,
            source_ref_external_allowed=False,
            observe_mode=False,
            deadline=time.monotonic() + 5,
            policy_snapshot=publisher.current_snapshot_binding() if binding is None else binding,
        )

    def require_action(edge: dict[str, Any] | None, expected: str, rule: str | None) -> dict[str, Any]:
        assert edge is not None, "the real resident must return an authenticated scoped result"
        assert edge["schema"] == "guard-hook-edge-result.v3" and edge["authority"] == "rust"
        assert edge["result"]["policy_action"] == expected
        assert edge["result"]["decision"] == ("allow" if expected == "allow" else "deny")
        assert publisher.result_binding_is_current(edge["policy_binding"])
        assert edge["receipt"]["rule_digest"] == capabilities.rule_digest
        identity = publisher.policy_rule_identity_for_result(edge["policy_binding"])
        if rule is None:
            assert identity is None and edge["policy_binding"]["selected_decision_id"] is None
        else:
            assert identity is not None and source is not None
            assert identity.to_dict() == {
                "policyId": "synthetic.expression-policy",
                "ruleId": rule,
                "policyVersion": "7",
            }
            assert identity.publication is not None
            assert identity.publication.bundle_version == 9
            assert identity.publication.bundle_hash == source.bundle_hash
        return edge

    try:
        publisher._publish_once()
        assert publisher.is_ready(), publisher.last_error
        configured_review = require_action(evaluate(), "review", None)
        configure_expression_fixture_policy(store)
        publisher.request_publish()
        assert not publisher.is_ready()
        publisher._publish_once()
        assert publisher.is_ready(), publisher.last_error
        before = require_action(evaluate(), "allow", None)
        assert before["receipt"]["policy_digest"] != configured_review["receipt"]["policy_digest"]
        source = publish_expression_source(store, workspace)
        assert not publisher.is_ready()
        publisher._publish_once()
        assert publisher.is_ready(), publisher.last_error
        blocked = require_action(evaluate(), "block", "block.expression")
        assert blocked["receipt"]["policy_digest"] != before["receipt"]["policy_digest"]
        # Expression normalization is an existing separate contract. All three
        # conditions must match, and the literal case comparison stays exact.
        require_action(evaluate(" \tprintf  'NativeBlocked' \n"), "block", "block.expression")
        for command in (
            "echo 'NativeBlocked'",
            "printf 'OtherBlocked'",
            "printf 'NativeAllowed'",
            "printf 'nativeBlocked'",
        ):
            require_action(evaluate(command), "allow", None)
        require_action(evaluate(harness="claude-code"), "allow", None)
        require_action(evaluate(cwd=other_workspace), "allow", None)
        require_action(
            evaluate(payload={**raw_payload(COMMAND), "artifact_id": "synthetic-unrelated-request"}), "allow", None
        )
        require_action(evaluate(payload={**raw_payload(COMMAND), "tool_name": "Shell"}), "allow", None)

        # The raw-byte selector is an additional AND condition, not a normalized
        # command-expression alias. Whitespace changes keep the expression true.
        require_action(evaluate(EXACT_COMMAND), "review", "review.exact-expression")
        require_action(evaluate(" " + EXACT_COMMAND + " "), "allow", None)
        assert all(row["artifact_id"] != ARTIFACT for row in store.list_policy_decisions())

        binding = publisher.current_snapshot_binding()
        assert binding is not None
        generation = binding["generation"]
        assert type(generation) is int
        assert evaluate(binding={**binding, "generation": generation + 1}) is None
        assert evaluate(binding={**binding, "source_input_digest": "0" * 64}) is None
        assert evaluate(binding={**binding, "policy_digest": "0" * 64}) is None

        # Use actual elapsed time: the resident and publisher must both stop
        # accepting the original lease before renewed inputs omit the old row.
        assert time.time() < source.block_expires_at.timestamp(), "fixture work exceeded its real authority lease"
        while time.time() <= source.block_expires_at.timestamp() + 0.03:
            time.sleep(min(0.25, max(0.01, source.block_expires_at.timestamp() + 0.03 - time.time())))
        assert not publisher.is_ready()
        assert not publisher.result_binding_is_current(blocked["policy_binding"])
        assert evaluate(binding=binding) is None
        publisher._publish_once()
        assert publisher.is_ready(), publisher.last_error
        require_action(evaluate(), "allow", None)
        renewed = require_action(evaluate(EXACT_COMMAND), "review", "review.exact-expression")
        assert publisher.current_snapshot_binding() is not None

        # require_action proves this renewed result is current and attributed.
        # Withdrawal must invalidate that fresh result, independently of the
        # expired block above. The raw IPC helper does not run HookWorker's
        # publisher admission fence, so it makes no synchronous disk-read claim.
        # A signed-source key withdrawal cannot become permissive empty input.
        keyring = store.get_sync_payload("policy_bundle_keyring")
        assert isinstance(keyring, dict)
        keys = keyring["keys"]
        assert isinstance(keys, list) and isinstance(keys[0], dict)
        keys[0]["state"] = "revoked"
        store.set_sync_payload("policy_bundle_keyring", keyring, datetime.now(timezone.utc).isoformat())
        publisher.request_publish()
        assert not publisher.result_binding_is_current(renewed["policy_binding"])
        assert publisher.policy_rule_identity_for_result(renewed["policy_binding"]) is None
        assert publisher.current_snapshot_binding() is None
        publisher._publish_once()
        assert not publisher.is_ready()
        assert publisher.last_error == "native_policy_authority_bundle_unavailable"
    finally:
        publisher.close()
        assert stop_native_resident(status.identity.path, store.guard_home, write_diagnostic=False).contained
