# pyright: reportUnusedCallResult=false
from __future__ import annotations

import itertools
from dataclasses import FrozenInstanceError, replace
from datetime import datetime, timezone
from typing import cast

import pytest

from codex_plugin_scanner.guard.models import GuardAction
from codex_plugin_scanner.guard.runtime.command_activity_contract import (
    COMMAND_ACTIVITY_SCHEMA_VERSION,
    ActivityApprovalReuseStatus,
    ActivityDecisionReason,
    ActivityLatencyBucket,
    ActivityMatchClass,
    ActivityParseConfidence,
    CommandActivity,
    CommandActivityEvidence,
    CommandActivityMatch,
    CommandExecutionStatus,
    CommandHookPhase,
    CommandProofLevel,
    CorrelationHandle,
    CorrelationKind,
    ReceiptLinkStatus,
    validate_activity_transition,
)
from codex_plugin_scanner.guard.runtime.effect_contract import EffectKind, UncertaintyKind
from codex_plugin_scanner.guard.runtime.extension_evidence import EvidenceSeverity, ExtensionRuleIdentity


def _identity(rule_id: str = "command.git.push") -> ExtensionRuleIdentity:
    return ExtensionRuleIdentity("command.git", "2.2.0", rule_id, "1.0.0")


def _correlation(kind: CorrelationKind = CorrelationKind.REQUEST, *, harness: str = "codex") -> CorrelationHandle:
    return CorrelationHandle(kind, harness, "key.v1", "a" * 64)


def _activity(
    *,
    status: CommandExecutionStatus = CommandExecutionStatus.ATTEMPTED,
    phase: CommandHookPhase = CommandHookPhase.PRE,
    proof: CommandProofLevel = CommandProofLevel.PRE_HOOK,
    policy_action: GuardAction | None = "allow",
    request_correlation: CorrelationHandle | None = None,
    session_correlation: CorrelationHandle | None = None,
    match_count: int = 1,
    controlling_rule_id: str | None = "command.git.push",
    decision_reason_code: ActivityDecisionReason | None = ActivityDecisionReason.EXTENSION_MATCH,
    parse_confidence: ActivityParseConfidence | None = ActivityParseConfidence.EXACT,
    uncertainty_class: UncertaintyKind | None = None,
    receipt_link_status: ReceiptLinkStatus = ReceiptLinkStatus.NOT_APPLICABLE,
    receipt_id: str | None = None,
    schema_version: str = COMMAND_ACTIVITY_SCHEMA_VERSION,
) -> CommandActivity:
    return CommandActivity(
        activity_id="activity:01",
        occurred_at=datetime(2026, 7, 18, 20, 0, tzinfo=timezone.utc),
        harness="codex",
        hook_phase=phase,
        execution_status=status,
        proof_level=proof,
        policy_action=policy_action,
        decision_reason_code=decision_reason_code if policy_action is not None else None,
        controlling_rule_id=controlling_rule_id,
        parse_confidence=parse_confidence,
        uncertainty_class=uncertainty_class,
        match_count=match_count,
        prompted=False,
        approval_reuse_status=ActivityApprovalReuseStatus.NOT_APPLICABLE,
        request_correlation=request_correlation,
        session_correlation=session_correlation,
        receipt_link_status=receipt_link_status,
        receipt_id=receipt_id,
        evaluation_latency_bucket=(
            ActivityLatencyBucket.LE_5_MS
            if status is not CommandExecutionStatus.UNPAIRED_POST
            else ActivityLatencyBucket.NOT_MEASURED
        ),
        persistence_latency_bucket=ActivityLatencyBucket.LE_2_MS,
        schema_version=schema_version,
    )


def _unpaired(phase: CommandHookPhase) -> CommandActivity:
    return _activity(
        status=CommandExecutionStatus.UNPAIRED_POST,
        phase=phase,
        proof=CommandProofLevel.UNPAIRED_POST,
        policy_action=None,
        match_count=0,
        controlling_rule_id=None,
        decision_reason_code=None,
        parse_confidence=None,
    )


def _match(
    ordinal: int = 0,
    *,
    identity: ExtensionRuleIdentity | None = None,
    match_class: ActivityMatchClass = ActivityMatchClass.UNSAFE,
    safe_variant_id: str | None = None,
) -> CommandActivityMatch:
    return CommandActivityMatch(
        activity_id="activity:01",
        ordinal=ordinal,
        identity=identity or _identity(),
        match_class=match_class,
        severity=EvidenceSeverity.HIGH,
        default_floor="review",
        effect_claims=frozenset({EffectKind.REMOTE_STATE_MUTATION}),
        safe_variant_id=safe_variant_id,
    )


def test_schema_is_versioned_immutable_and_uses_exact_typed_boundaries() -> None:
    activity = _activity()

    assert activity.schema_version == "1.0.0"
    with pytest.raises(FrozenInstanceError):
        activity.__setattr__("match_count", 2)
    with pytest.raises(ValueError, match="schema version"):
        _activity(schema_version="1.0.1")
    with pytest.raises(ValueError, match="CommandExecutionStatus"):
        replace(activity, execution_status=cast(CommandExecutionStatus, cast(object, "attempted")))
    with pytest.raises(ValueError, match="UTC datetime"):
        replace(activity, occurred_at=datetime(2026, 7, 18, 20, 0))


def test_phase_status_proof_matrix_is_closed_and_exhaustive() -> None:
    legal = {
        (CommandHookPhase.PRE, status, CommandProofLevel.PRE_HOOK)
        for status in (
            CommandExecutionStatus.ATTEMPTED,
            CommandExecutionStatus.PREVENTED,
            CommandExecutionStatus.ALLOWED_UNCONFIRMED,
        )
    } | {
        (
            CommandHookPhase.POST_SUCCESS,
            CommandExecutionStatus.CONFIRMED_SUCCESS,
            CommandProofLevel.POST_HOOK,
        ),
        (
            CommandHookPhase.POST_FAILURE,
            CommandExecutionStatus.CONFIRMED_FAILURE,
            CommandProofLevel.POST_HOOK,
        ),
        (
            CommandHookPhase.POST_SUCCESS,
            CommandExecutionStatus.UNPAIRED_POST,
            CommandProofLevel.UNPAIRED_POST,
        ),
        (
            CommandHookPhase.POST_FAILURE,
            CommandExecutionStatus.UNPAIRED_POST,
            CommandProofLevel.UNPAIRED_POST,
        ),
    }
    for phase, status, proof in itertools.product(CommandHookPhase, CommandExecutionStatus, CommandProofLevel):
        request = (
            _correlation()
            if status in {CommandExecutionStatus.CONFIRMED_SUCCESS, CommandExecutionStatus.CONFIRMED_FAILURE}
            else None
        )
        factory = _unpaired if status is CommandExecutionStatus.UNPAIRED_POST else None
        if (phase, status, proof) in legal:
            result = (
                factory(phase)
                if factory is not None
                else _activity(status=status, phase=phase, proof=proof, request_correlation=request)
            )
            assert result.execution_status is status
        else:
            with pytest.raises(ValueError):
                _activity(status=status, phase=phase, proof=proof, request_correlation=request)


def test_session_only_correlation_never_confirms_execution() -> None:
    session = _correlation(CorrelationKind.SESSION)

    with pytest.raises(ValueError, match="strong request correlation"):
        _activity(
            status=CommandExecutionStatus.CONFIRMED_SUCCESS,
            phase=CommandHookPhase.POST_SUCCESS,
            proof=CommandProofLevel.POST_HOOK,
            session_correlation=session,
        )
    assert _unpaired(CommandHookPhase.POST_SUCCESS).execution_status is CommandExecutionStatus.UNPAIRED_POST
    assert replace(_unpaired(CommandHookPhase.POST_SUCCESS), session_correlation=session).session_correlation == session


def test_unpaired_post_cannot_invent_pre_hook_facts() -> None:
    unpaired = _unpaired(CommandHookPhase.POST_FAILURE)

    with pytest.raises(ValueError, match="cannot invent"):
        replace(unpaired, match_count=1)
    with pytest.raises(ValueError, match="cannot invent"):
        replace(unpaired, policy_action="allow")
    with pytest.raises(ValueError, match="cannot claim"):
        replace(unpaired, request_correlation=_correlation())


def test_lifecycle_transitions_are_idempotent_and_fail_closed() -> None:
    request = _correlation()
    attempted = _activity(request_correlation=request)
    allowed = replace(
        attempted,
        execution_status=CommandExecutionStatus.ALLOWED_UNCONFIRMED,
    )
    confirmed = replace(
        allowed,
        hook_phase=CommandHookPhase.POST_SUCCESS,
        execution_status=CommandExecutionStatus.CONFIRMED_SUCCESS,
        proof_level=CommandProofLevel.POST_HOOK,
    )
    prevented = replace(attempted, execution_status=CommandExecutionStatus.PREVENTED)

    validate_activity_transition(attempted, allowed)
    validate_activity_transition(allowed, confirmed)
    validate_activity_transition(confirmed, confirmed)
    validate_activity_transition(attempted, prevented)
    with pytest.raises(ValueError, match="invalid or conflicting"):
        validate_activity_transition(prevented, confirmed)
    conflicting = replace(
        confirmed,
        hook_phase=CommandHookPhase.POST_FAILURE,
        execution_status=CommandExecutionStatus.CONFIRMED_FAILURE,
    )
    with pytest.raises(ValueError, match="invalid or conflicting"):
        validate_activity_transition(confirmed, conflicting)
    with pytest.raises(ValueError, match="cannot change"):
        validate_activity_transition(allowed, replace(allowed, prompted=True))


def test_review_or_stronger_activity_requires_exact_receipt_link() -> None:
    with pytest.raises(ValueError, match="linked receipt"):
        _activity(status=CommandExecutionStatus.PREVENTED, policy_action="review")

    reviewed = _activity(
        status=CommandExecutionStatus.PREVENTED,
        policy_action="review",
        receipt_link_status=ReceiptLinkStatus.LINKED,
        receipt_id="receipt:01",
    )
    assert reviewed.receipt_id == "receipt:01"
    with pytest.raises(ValueError, match="requires receipt_id"):
        replace(reviewed, receipt_id=None)


def test_non_exact_parse_requires_bounded_uncertainty() -> None:
    with pytest.raises(ValueError, match="requires a bounded uncertainty"):
        _activity(parse_confidence=ActivityParseConfidence.UNCERTAIN)
    with pytest.raises(ValueError, match="exact parse"):
        _activity(uncertainty_class=UncertaintyKind.PARTIAL_PARSE)

    uncertain = _activity(
        parse_confidence=ActivityParseConfidence.FALLBACK,
        uncertainty_class=UncertaintyKind.PARTIAL_PARSE,
    )
    assert uncertain.uncertainty_class is UncertaintyKind.PARTIAL_PARSE


def test_pre_and_confirmed_rows_require_complete_bounded_decision_facts() -> None:
    activity = _activity()

    with pytest.raises(ValueError, match="complete bounded decision facts"):
        replace(activity, policy_action=None, decision_reason_code=None)
    with pytest.raises(ValueError, match="no-match reason"):
        replace(activity, decision_reason_code=ActivityDecisionReason.NO_MATCH)
    with pytest.raises(ValueError, match="no-match reason"):
        _activity(match_count=0, controlling_rule_id=None, decision_reason_code=ActivityDecisionReason.POLICY)


def test_match_projection_distinguishes_safe_variants_and_rejects_untyped_evidence() -> None:
    safe = _match(match_class=ActivityMatchClass.SAFE_VARIANT, safe_variant_id="dry.run")
    assert safe.match_class is ActivityMatchClass.SAFE_VARIANT
    with pytest.raises(ValueError, match="safe_variant_id"):
        _match(match_class=ActivityMatchClass.SAFE_VARIANT)
    with pytest.raises(ValueError, match="safe_variant_id"):
        _match(safe_variant_id="dry.run")
    with pytest.raises(ValueError, match="EffectKind"):
        replace(
            _match(),
            effect_claims=frozenset({cast(EffectKind, cast(object, "remote-state-mutation"))}),
        )


def test_evidence_binds_one_activity_to_exact_ordered_unique_matches() -> None:
    first = _match()
    second = _match(1, identity=_identity("command.git.delete"))
    activity = replace(_activity(), match_count=2)

    evidence = CommandActivityEvidence(activity, (first, second))
    assert evidence.activity.match_count == 2
    with pytest.raises(ValueError, match="match_count"):
        CommandActivityEvidence(_activity(), ())
    with pytest.raises(ValueError, match="ordinals"):
        CommandActivityEvidence(activity, (second, first))
    with pytest.raises(ValueError, match="repeat"):
        CommandActivityEvidence(activity, (first, replace(first, ordinal=1)))
    version_duplicate = replace(
        first,
        ordinal=1,
        identity=ExtensionRuleIdentity("command.git", "2.2.0", "command.git.push", "1.0.1"),
    )
    with pytest.raises(ValueError, match="logical rule_id"):
        CommandActivityEvidence(activity, (first, version_duplicate))
    with pytest.raises(ValueError, match="controlling_rule_id"):
        CommandActivityEvidence(replace(_activity(), controlling_rule_id="command.git.other"), (first,))


def test_unmatched_ordinary_command_has_one_activity_and_zero_match_rows() -> None:
    activity = _activity(
        match_count=0,
        controlling_rule_id=None,
        decision_reason_code=ActivityDecisionReason.NO_MATCH,
    )

    evidence = CommandActivityEvidence(activity, ())

    assert evidence.activity.match_count == 0
    assert evidence.matches == ()
