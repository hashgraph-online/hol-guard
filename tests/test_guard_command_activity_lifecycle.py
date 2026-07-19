from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone

import pytest

from codex_plugin_scanner.guard.models import GuardAction
from codex_plugin_scanner.guard.runtime.command_activity_contract import (
    ActivityApprovalReuseStatus,
    ActivityDecisionReason,
    ActivityLatencyBucket,
    ActivityParseConfidence,
    CommandExecutionStatus,
    CommandHookPhase,
    CommandProofLevel,
    CorrelationHandle,
    CorrelationKind,
    ReceiptLinkStatus,
    validate_activity_transition,
)
from codex_plugin_scanner.guard.runtime.command_activity_lifecycle import (
    CommandActivityDecisionFacts,
    build_correlated_post_activity,
    build_correlated_post_evidence,
    build_pre_hook_evidence,
    build_unpaired_post_evidence,
)
from codex_plugin_scanner.guard.runtime.command_evaluation import evaluate_command
from codex_plugin_scanner.guard.runtime.effect_contract import EffectKind, UncertaintyKind

NOW = datetime(2026, 7, 18, 20, 0, tzinfo=timezone.utc)


def _correlation(kind: CorrelationKind = CorrelationKind.REQUEST, *, digest: str = "a" * 64) -> CorrelationHandle:
    return CorrelationHandle(kind=kind, harness="codex", key_id="key.v1", digest=digest)


def _decision(
    *,
    action: GuardAction = "allow",
    reason: ActivityDecisionReason = ActivityDecisionReason.EXTENSION_MATCH,
    receipt_id: str | None = None,
) -> CommandActivityDecisionFacts:
    return CommandActivityDecisionFacts(
        policy_action=action,
        decision_reason_code=reason,
        prompted=action == "review",
        approval_reuse_status=ActivityApprovalReuseStatus.NOT_APPLICABLE,
        receipt_id=receipt_id,
    )


def test_pre_hook_uses_only_authoritative_evaluation_and_final_decision_facts() -> None:
    evaluation = evaluate_command("rm -rf ./generated-output")
    request = _correlation()
    evidence = build_pre_hook_evidence(
        evaluation,
        _decision(action="review", receipt_id="receipt:01"),
        activity_id="activity:01",
        occurred_at=NOW,
        harness="codex",
        request_correlation=request,
        evaluation_latency_bucket=ActivityLatencyBucket.LE_2_MS,
    )

    activity = evidence.activity
    match = evidence.matches[0]
    assert activity.execution_status is CommandExecutionStatus.PREVENTED
    assert activity.policy_action == "review"
    assert activity.prompted is True
    assert activity.receipt_link_status is ReceiptLinkStatus.LINKED
    assert activity.receipt_id == "receipt:01"
    assert activity.controlling_rule_id == "command.filesystem.recursive-delete"
    assert activity.parse_confidence is ActivityParseConfidence.EXACT
    assert activity.request_correlation == request
    assert match.identity.extension_id == "command.filesystem"
    assert match.identity.extension_version == "1.0.0"
    assert match.identity.rule_id == "command.filesystem.recursive-delete"
    assert match.identity.rule_version == "1.0.0"
    assert match.effect_claims == frozenset({EffectKind.DESTRUCTIVE_OR_IRREVERSIBLE_OPERATION})
    assert match.default_floor == "review"


def test_allow_and_warn_are_allowed_unconfirmed_while_review_or_stronger_is_prevented() -> None:
    evaluation = evaluate_command("rm -rf ./generated-output")
    for action in ("allow", "warn"):
        evidence = build_pre_hook_evidence(
            evaluation,
            _decision(action=action),
            activity_id=f"activity:{action}",
            occurred_at=NOW,
            harness="codex",
        )
        assert evidence.activity.execution_status is CommandExecutionStatus.ALLOWED_UNCONFIRMED
    for action in ("review", "require-reapproval", "sandbox-required", "block"):
        evidence = build_pre_hook_evidence(
            evaluation,
            _decision(action=action, receipt_id=f"receipt:{action}"),
            activity_id=f"activity:{action}",
            occurred_at=NOW,
            harness="codex",
        )
        assert evidence.activity.execution_status is CommandExecutionStatus.PREVENTED


def test_required_critical_rule_retains_the_evaluators_block_floor() -> None:
    evidence = build_pre_hook_evidence(
        evaluate_command("mkfs /dev/example"),
        _decision(action="block", receipt_id="receipt:critical"),
        activity_id="activity:critical",
        occurred_at=NOW,
        harness="codex",
    )

    assert evidence.matches[0].default_floor == "block"


def test_no_match_reason_is_exact_and_does_not_invent_rule_evidence() -> None:
    evaluation = evaluate_command("printf routine")
    evidence = build_pre_hook_evidence(
        evaluation,
        _decision(reason=ActivityDecisionReason.NO_MATCH),
        activity_id="activity:no-match",
        occurred_at=NOW,
        harness="codex",
    )

    assert evidence.matches == ()
    assert evidence.activity.match_count == 0
    assert evidence.activity.controlling_rule_id is None
    with pytest.raises(ValueError, match="no-match"):
        _ = build_pre_hook_evidence(
            evaluation,
            _decision(),
            activity_id="activity:bad-reason",
            occurred_at=NOW,
            harness="codex",
        )


def test_parser_uncertainty_is_bounded_without_storing_parser_input() -> None:
    exact = evaluate_command("rm -rf ./generated-output")
    uncertain_command = replace(
        exact.command,
        confidence="uncertain",
        uncertainty_reason="command_token_limit_exceeded",
    )
    uncertain = replace(exact, command=uncertain_command)
    evidence = build_pre_hook_evidence(
        uncertain,
        _decision(reason=ActivityDecisionReason.UNCERTAINTY),
        activity_id="activity:uncertain",
        occurred_at=NOW,
        harness="codex",
    )

    assert evidence.activity.parse_confidence is ActivityParseConfidence.UNCERTAIN
    assert evidence.activity.uncertainty_class is UncertaintyKind.PARSER_BUDGET_EXHAUSTED
    assert "generated-output" not in repr(evidence)


def test_correlated_success_and_failure_preserve_pre_hook_facts() -> None:
    request = _correlation()
    pre = build_pre_hook_evidence(
        evaluate_command("rm -rf ./generated-output"),
        _decision(),
        activity_id="activity:paired",
        occurred_at=NOW,
        harness="codex",
        request_correlation=request,
    )

    for succeeded, phase, status in (
        (True, CommandHookPhase.POST_SUCCESS, CommandExecutionStatus.CONFIRMED_SUCCESS),
        (False, CommandHookPhase.POST_FAILURE, CommandExecutionStatus.CONFIRMED_FAILURE),
    ):
        post = build_correlated_post_evidence(
            pre,
            request_correlation=request,
            succeeded=succeeded,
            persistence_latency_bucket=ActivityLatencyBucket.LE_5_MS,
        )
        assert post.activity.hook_phase is phase
        assert post.activity.execution_status is status
        assert post.activity.proof_level is CommandProofLevel.POST_HOOK
        assert post.matches == pre.matches
        validate_activity_transition(pre.activity, post.activity)


def test_correlated_post_activity_accepts_the_parent_row_returned_by_storage() -> None:
    request = _correlation()
    pre = build_pre_hook_evidence(
        evaluate_command("rm -rf ./generated-output"),
        _decision(),
        activity_id="activity:stored",
        occurred_at=NOW,
        harness="codex",
        request_correlation=request,
    )

    post = build_correlated_post_activity(
        pre.activity,
        request_correlation=request,
        succeeded=True,
    )

    assert post.execution_status is CommandExecutionStatus.CONFIRMED_SUCCESS
    assert post.activity_id == pre.activity.activity_id
    validate_activity_transition(pre.activity, post)


def test_correlated_post_rejects_missing_mismatched_or_prevented_pre_hook() -> None:
    request = _correlation()
    allowed = build_pre_hook_evidence(
        evaluate_command("rm -rf ./generated-output"),
        _decision(),
        activity_id="activity:paired",
        occurred_at=NOW,
        harness="codex",
        request_correlation=request,
    )
    with pytest.raises(ValueError, match="exact pre-hook"):
        _ = build_correlated_post_evidence(
            allowed,
            request_correlation=_correlation(digest="b" * 64),
            succeeded=True,
        )
    without_request = replace(allowed, activity=replace(allowed.activity, request_correlation=None))
    with pytest.raises(ValueError, match="exact pre-hook"):
        _ = build_correlated_post_evidence(without_request, request_correlation=request, succeeded=True)
    prevented = build_pre_hook_evidence(
        evaluate_command("rm -rf ./generated-output"),
        _decision(action="review", receipt_id="receipt:01"),
        activity_id="activity:prevented",
        occurred_at=NOW,
        harness="codex",
        request_correlation=request,
    )
    with pytest.raises(ValueError, match="allowed-unconfirmed"):
        _ = build_correlated_post_evidence(prevented, request_correlation=request, succeeded=True)


def test_unpaired_post_claims_no_decision_match_receipt_or_request_proof() -> None:
    session = _correlation(CorrelationKind.SESSION)
    evidence = build_unpaired_post_evidence(
        activity_id="activity:unpaired",
        occurred_at=NOW,
        harness="codex",
        succeeded=False,
        session_correlation=session,
    )

    activity = evidence.activity
    assert activity.execution_status is CommandExecutionStatus.UNPAIRED_POST
    assert activity.hook_phase is CommandHookPhase.POST_FAILURE
    assert activity.proof_level is CommandProofLevel.UNPAIRED_POST
    assert activity.policy_action is None
    assert activity.request_correlation is None
    assert activity.session_correlation == session
    assert activity.receipt_id is None
    assert activity.match_count == 0
    assert evidence.matches == ()


def test_runtime_construction_exposes_no_command_or_matcher_content_fields() -> None:
    evaluation = evaluate_command("rm -rf /private/forbidden-sentinel")
    evidence = build_pre_hook_evidence(
        evaluation,
        _decision(),
        activity_id="activity:privacy",
        occurred_at=NOW,
        harness="codex",
    )

    serialized = repr(evidence)
    for forbidden in ("forbidden-sentinel", "raw_text", "normalized_text", "matcher_evidence"):
        assert forbidden not in serialized
