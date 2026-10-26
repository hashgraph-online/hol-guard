"""Pure construction of privacy-safe command activity lifecycle evidence."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime
from types import MappingProxyType
from typing import Final

from codex_plugin_scanner.guard.models import GuardAction

from .command_activity_contract import (
    ActivityApprovalReuseStatus,
    ActivityLatencyBucket,
    CommandActivity,
    CommandActivityEvidence,
    CommandExecutionStatus,
    CommandHookPhase,
    CommandProofLevel,
    CorrelationHandle,
    ReceiptLinkStatus,
)
from .effect_contract import EffectKind, UncertaintyKind
from .extension_evidence import EvidenceSeverity
from .generated_command_catalog import CommandRuleMode

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

# The decision plane claims `process-execution` for a risk class the effect
# vocabulary does not name (`effect_claims`, command_decision_adapter.rs), and
# this record says what that plane decided. Raising here instead dropped the
# whole activity: the only caller records best effort, so an unmapped class on
# a shipped rule left a `pre_record_failed` count and no evidence at all.
_UNMAPPED_RISK_CLASS_EFFECTS: Final = frozenset({EffectKind.PROCESS_EXECUTION})

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
