"""Recorded review provenance comes from the exact authenticated winning rule."""

from __future__ import annotations

import sqlite3
from dataclasses import replace
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.approvals import queue_blocked_approvals
from codex_plugin_scanner.guard.consumer.service import evaluate_detection
from codex_plugin_scanner.guard.decision_projection_boundaries import canonical_approval_decision
from codex_plugin_scanner.guard.models import PolicyDecision
from codex_plugin_scanner.guard.policy_rule_identity import PolicyRuleIdentity, canonical_rule_identity
from codex_plugin_scanner.guard.review_contracts import (
    build_local_review_request_claim,
    compute_local_review_request_claim_hash,
)
from codex_plugin_scanner.guard.review_oauth_binding import GuardReviewOAuthMetadata
from codex_plugin_scanner.guard.runtime.approval_reuse import bind_saved_policy_identity, evaluate_approval_reuse
from codex_plugin_scanner.guard.runtime.decisions import AuthoritativeGuardDecision, build_authoritative_decision
from tests.test_canonical_policy_row_authority import _ARTIFACT, _NOW, _activated_store
from tests.test_guard_consumer_approval_precedence import _artifact, _config, _detection

_IDENTITY = {"policyId": "synthetic.policy", "ruleId": "synthetic.rule", "policyVersion": "8"}


@pytest.mark.parametrize("consume", [False, True])
def test_lookup_returns_identity_of_the_authenticated_canonical_winner(tmp_path: Path, consume: bool) -> None:
    store = _activated_store(tmp_path, action="review")
    selected = store.resolve_policy_decision_lookup("codex", _ARTIFACT, now=_NOW, consume_one_shot=consume)["decision"]
    assert selected is not None
    assert {key: selected.get(key) for key in _IDENTITY} == _IDENTITY
    store.upsert_policy(
        PolicyDecision(harness="codex", scope="artifact", action="block", artifact_id=_ARTIFACT, source="local"),
        "2026-09-17T00:00:01Z",
    )
    newer = store.resolve_policy_decision_lookup(
        "codex", _ARTIFACT, now="2026-09-17T00:00:02Z", consume_one_shot=consume
    )["decision"]
    assert newer is not None and newer["source"] == "local"
    assert not any(key in newer for key in _IDENTITY)


def test_canonical_document_revision_is_distinct_from_delivery_revision() -> None:
    bundle = {
        "contractVersion": "guard-policy-bundle.v2",
        "bundleVersion": 42,
        "payload": {"metadata": {"id": "synthetic.policy", "revision": 8}},
    }
    identity = canonical_rule_identity(bundle, "synthetic.rule")
    assert identity is not None and identity.to_dict() == _IDENTITY
    assert canonical_rule_identity({**bundle, "contractVersion": "guard-policy-bundle.v1"}, "synthetic.rule") is None


def test_signed_lookup_uses_document_revision_when_delivery_revision_differs(tmp_path: Path) -> None:
    store = _activated_store(tmp_path, action="review", bundle_version=42)
    selected = store.resolve_policy_decision_lookup("codex", _ARTIFACT, now=_NOW, consume_one_shot=False)["decision"]
    assert selected is not None and selected["policyVersion"] == "8"


def test_tampered_materialized_rule_identity_cannot_be_attributed(tmp_path: Path) -> None:
    store = _activated_store(tmp_path, action="review")
    with sqlite3.connect(store.path) as connection:
        connection.execute("update policy_decisions set owner = 'different.rule'")
    assert (
        store.resolve_policy_decision_lookup("codex", _ARTIFACT, now=_NOW, consume_one_shot=False)["decision"] is None
    )


@pytest.mark.parametrize(
    "current,saved,reason,expected",
    [
        ("allow", "review", None, True),
        ("review", "block", None, True),
        ("block", "block", None, False),
        ("review", "review", None, False),
        ("block", "review", None, False),
        ("allow", "review", "approval_reuse_integrity_failure", False),
    ],
)
def test_only_the_rule_that_changes_the_outcome_is_attributed(current, saved, reason, expected) -> None:
    reuse = bind_saved_policy_identity(
        evaluate_approval_reuse(current, saved, validation_reason=reason), _IDENTITY, validation_reason=reason
    )
    assert bool(reuse.policy_rule_evidence(reuse.action)) is expected
    assert reuse.policy_rule_evidence(reuse.action, overridden=True) == {}


@pytest.mark.parametrize(
    "mutation",
    [
        {"policyId": None},
        {"ruleId": None},
        {"policyVersion": None},
        {"policyVersion": "08"},
        {"policyVersion": "-1"},
        {"policyId": "x" * 129},
        {"ruleId": "rule\n"},
        {"policyId": "policý"},
    ],
)
def test_malformed_or_partial_identity_is_not_projected(mutation) -> None:
    raw = {"guard_action": "review", "action": "ask", **_IDENTITY, **mutation}
    assert PolicyRuleIdentity.from_mapping(raw) is None
    decision = canonical_approval_decision("review", raw, reject_contradiction=True)
    assert "policyId" not in decision.decision_v2_json and "ruleId" not in decision.decision_v2_json


def test_authoritative_projection_round_trip_preserves_complete_identity() -> None:
    decision = build_authoritative_decision(
        "review",
        reason="synthetic rule requires review",
        composition_trace={"current_action": "allow", "saved_action": "review", **_IDENTITY},
        authority_finalized=True,
    )
    assert AuthoritativeGuardDecision.from_dict(decision.to_dict()) == decision
    assert {key: decision.to_artifact_projection()["decision_v2_json"][key] for key in _IDENTITY} == _IDENTITY
    inconsistent = decision.to_dict()
    inconsistent["decision_v2"]["ruleId"] = "different.rule"
    with pytest.raises(ValueError, match="derive entirely"):
        AuthoritativeGuardDecision.from_dict(inconsistent)


def test_real_consumer_queue_and_claim_keep_original_rule_after_source_changes(tmp_path: Path) -> None:
    store = _activated_store(tmp_path, action="review")
    artifact = replace(_artifact(tmp_path), artifact_id=_ARTIFACT, metadata={"guard_default_action": "allow"})
    detection = _detection(artifact)
    evaluation = evaluate_detection(detection, store, _config(tmp_path), default_action="allow", persist=False)
    result = evaluation["artifacts"][0]
    assert result["policy_action"] == "review"
    assert {key: result["decision_v2_json"].get(key) for key in _IDENTITY} == _IDENTITY
    queued = queue_blocked_approvals(
        detection=detection,
        evaluation=evaluation,
        store=store,
        approval_center_url="http://localhost",
        now=_NOW,
        notify=False,
    )
    assert len(queued) == 1
    request = store.get_approval_request(queued[0]["request_id"])
    assert request is not None
    store.clear_policy_bundle_authority(
        "2026-09-17T00:01:00Z", policy_bundle_last_error={"reason": "synthetic replacement"}
    )
    oauth = GuardReviewOAuthMetadata(
        "synthetic-device",
        None,
        "synthetic-grant",
        "synthetic-installation",
        "synthetic-machine",
        "hol-guard",
        "workspace-alpha",
    )
    claim = build_local_review_request_claim(request_row=request, oauth=oauth, store=store)
    assert {key: claim.get(key) for key in _IDENTITY} == _IDENTITY
    assert compute_local_review_request_claim_hash(claim) == claim["claimHash"]
    for key in _IDENTITY:
        assert compute_local_review_request_claim_hash({**claim, key: "changed"}) != claim["claimHash"]
