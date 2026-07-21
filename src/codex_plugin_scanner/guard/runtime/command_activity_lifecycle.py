"""Pure construction of privacy-safe command activity lifecycle evidence."""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime
from types import MappingProxyType
from typing import Final, cast

from codex_plugin_scanner.guard.action_lattice import guard_action_severity, is_guard_action
from codex_plugin_scanner.guard.models import GuardAction

from .command_activity_contract import (
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
    ReceiptLinkStatus,
)
from .command_evaluation import CompositeCommandEvaluation, OwnedCommandRuleMatch
from .command_risk_effects import command_risk_effects
from .command_rules import CommandRuleMode
from .effect_contract import UncertaintyKind
from .extension_evidence import EvidenceSeverity, ExtensionRuleIdentity


@dataclass(frozen=True, slots=True)
class CommandActivityDecisionFacts:
    """Authoritative final decision facts supplied by the hook orchestrator."""

    policy_action: GuardAction
    decision_reason_code: ActivityDecisionReason
    prompted: bool
    approval_reuse_status: ActivityApprovalReuseStatus
    receipt_id: str | None

    def __post_init__(self) -> None:
        if not is_guard_action(self.policy_action):
            raise ValueError("policy_action must be a canonical GuardAction")
        if not isinstance(cast(object, self.decision_reason_code), ActivityDecisionReason):
            raise ValueError("decision_reason_code must be an ActivityDecisionReason")
        if type(self.prompted) is not bool:
            raise ValueError("prompted must be a boolean")
        if not isinstance(cast(object, self.approval_reuse_status), ActivityApprovalReuseStatus):
            raise ValueError("approval_reuse_status must be an ActivityApprovalReuseStatus")


_RULE_MODE_FLOOR: Final[dict[CommandRuleMode, GuardAction]] = {
    "disabled": "allow",
    "monitor": "warn",
    "review": "review",
    "enforce": "block",
    "required": "review",
}
_SEVERITY: Final = {
    "low": EvidenceSeverity.LOW,
    "medium": EvidenceSeverity.MEDIUM,
    "high": EvidenceSeverity.HIGH,
    "critical": EvidenceSeverity.CRITICAL,
}
_UNCERTAINTY_REASON: Final = MappingProxyType(
    {
        "command_byte_limit_exceeded": UncertaintyKind.PARSER_BUDGET_EXHAUSTED,
        "command_segment_limit_exceeded": UncertaintyKind.PARSER_BUDGET_EXHAUSTED,
        "command_token_limit_exceeded": UncertaintyKind.PARSER_BUDGET_EXHAUSTED,
        "embedded_command_limit_exceeded": UncertaintyKind.PARSER_BUDGET_EXHAUSTED,
        "malformed_shell_quoting": UncertaintyKind.MALFORMED_INPUT,
        "wrapper_normalization_limit_exceeded": UncertaintyKind.PARSER_BUDGET_EXHAUSTED,
    }
)


def build_pre_hook_evidence(
    evaluation: CompositeCommandEvaluation,
    decision: CommandActivityDecisionFacts,
    *,
    activity_id: str,
    occurred_at: datetime,
    harness: str,
    request_correlation: CorrelationHandle | None = None,
    session_correlation: CorrelationHandle | None = None,
    evaluation_latency_bucket: ActivityLatencyBucket = ActivityLatencyBucket.NOT_MEASURED,
    persistence_latency_bucket: ActivityLatencyBucket = ActivityLatencyBucket.NOT_MEASURED,
) -> CommandActivityEvidence:
    """Build final pre-hook evidence without evaluating, persisting, or mutating policy."""

    if not isinstance(cast(object, evaluation), CompositeCommandEvaluation):
        raise ValueError("evaluation must be a CompositeCommandEvaluation")
    matches = tuple(_activity_match(activity_id, ordinal, owned) for ordinal, owned in enumerate(evaluation.matches))
    _validate_reason_matches(decision.decision_reason_code, matches)
    receipt_status = ReceiptLinkStatus.LINKED if decision.receipt_id is not None else ReceiptLinkStatus.NOT_APPLICABLE
    activity = CommandActivity(
        activity_id=activity_id,
        occurred_at=occurred_at,
        harness=harness,
        hook_phase=CommandHookPhase.PRE,
        execution_status=(
            CommandExecutionStatus.PREVENTED
            if guard_action_severity(decision.policy_action) >= guard_action_severity("review")
            else CommandExecutionStatus.ALLOWED_UNCONFIRMED
        ),
        proof_level=CommandProofLevel.PRE_HOOK,
        policy_action=decision.policy_action,
        decision_reason_code=decision.decision_reason_code,
        controlling_rule_id=evaluation.controlling_rule_id,
        parse_confidence=ActivityParseConfidence(evaluation.command.confidence),
        uncertainty_class=_uncertainty_kind(evaluation),
        match_count=len(matches),
        prompted=decision.prompted,
        approval_reuse_status=decision.approval_reuse_status,
        request_correlation=request_correlation,
        session_correlation=session_correlation,
        receipt_link_status=receipt_status,
        receipt_id=decision.receipt_id,
        evaluation_latency_bucket=evaluation_latency_bucket,
        persistence_latency_bucket=persistence_latency_bucket,
    )
    return CommandActivityEvidence(activity=activity, matches=matches)


def build_correlated_post_evidence(
    previous: CommandActivityEvidence,
    *,
    request_correlation: CorrelationHandle,
    succeeded: bool,
    persistence_latency_bucket: ActivityLatencyBucket = ActivityLatencyBucket.NOT_MEASURED,
) -> CommandActivityEvidence:
    """Promote an evidence value while preserving its immutable rule matches."""

    activity = build_correlated_post_activity(
        previous.activity,
        request_correlation=request_correlation,
        succeeded=succeeded,
        persistence_latency_bucket=persistence_latency_bucket,
    )
    return CommandActivityEvidence(activity=activity, matches=previous.matches)


def build_correlated_post_activity(
    previous: CommandActivity,
    *,
    request_correlation: CorrelationHandle,
    succeeded: bool,
    persistence_latency_bucket: ActivityLatencyBucket = ActivityLatencyBucket.NOT_MEASURED,
) -> CommandActivity:
    """Promote a stored parent row only when the exact strong request handle matches."""

    if previous.execution_status is not CommandExecutionStatus.ALLOWED_UNCONFIRMED:
        raise ValueError("only allowed-unconfirmed activity can receive post-hook proof")
    if previous.request_correlation is None or previous.request_correlation != request_correlation:
        raise ValueError("post-hook proof requires the exact pre-hook request correlation")
    return replace(
        previous,
        hook_phase=CommandHookPhase.POST_SUCCESS if succeeded else CommandHookPhase.POST_FAILURE,
        execution_status=(
            CommandExecutionStatus.CONFIRMED_SUCCESS if succeeded else CommandExecutionStatus.CONFIRMED_FAILURE
        ),
        proof_level=CommandProofLevel.POST_HOOK,
        persistence_latency_bucket=persistence_latency_bucket,
    )


def build_unpaired_post_evidence(
    *,
    activity_id: str,
    occurred_at: datetime,
    harness: str,
    succeeded: bool,
    session_correlation: CorrelationHandle | None = None,
    persistence_latency_bucket: ActivityLatencyBucket = ActivityLatencyBucket.NOT_MEASURED,
) -> CommandActivityEvidence:
    """Build explicit post-hook evidence that claims no pre-hook decision or command facts."""

    activity = CommandActivity(
        activity_id=activity_id,
        occurred_at=occurred_at,
        harness=harness,
        hook_phase=CommandHookPhase.POST_SUCCESS if succeeded else CommandHookPhase.POST_FAILURE,
        execution_status=CommandExecutionStatus.UNPAIRED_POST,
        proof_level=CommandProofLevel.UNPAIRED_POST,
        policy_action=None,
        decision_reason_code=None,
        controlling_rule_id=None,
        parse_confidence=None,
        uncertainty_class=None,
        match_count=0,
        prompted=False,
        approval_reuse_status=ActivityApprovalReuseStatus.NOT_APPLICABLE,
        request_correlation=None,
        session_correlation=session_correlation,
        receipt_link_status=ReceiptLinkStatus.NOT_APPLICABLE,
        receipt_id=None,
        evaluation_latency_bucket=ActivityLatencyBucket.NOT_MEASURED,
        persistence_latency_bucket=persistence_latency_bucket,
    )
    return CommandActivityEvidence(activity=activity, matches=())


def _activity_match(activity_id: str, ordinal: int, owned: OwnedCommandRuleMatch) -> CommandActivityMatch:
    effects = command_risk_effects(owned.match.rule.risk_classes)
    rule = owned.match.rule
    default_floor = _RULE_MODE_FLOOR[rule.default_mode]
    if owned.extension.required:
        default_floor = "block" if rule.severity == "critical" else "review"
    return CommandActivityMatch(
        activity_id=activity_id,
        ordinal=ordinal,
        identity=ExtensionRuleIdentity(
            extension_id=owned.extension.extension_id,
            extension_version=owned.extension.version,
            rule_id=rule.rule_id,
            rule_version=owned.extension.version,
        ),
        match_class=ActivityMatchClass.UNSAFE,
        severity=_SEVERITY[rule.severity],
        default_floor=default_floor,
        effect_claims=frozenset(effects),
    )


def _uncertainty_kind(evaluation: CompositeCommandEvaluation) -> UncertaintyKind | None:
    command = evaluation.command
    if command.confidence == "exact":
        return None
    reason = command.uncertainty_reason
    if reason is not None and reason.startswith("unsupported_"):
        return UncertaintyKind.UNSUPPORTED_INPUT
    return _UNCERTAINTY_REASON.get(reason or "", UncertaintyKind.PARTIAL_PARSE)


def _validate_reason_matches(
    reason: ActivityDecisionReason,
    matches: tuple[CommandActivityMatch, ...],
) -> None:
    if (not matches) != (reason is ActivityDecisionReason.NO_MATCH):
        raise ValueError("no-match decision reason must correspond exactly to no rule matches")
