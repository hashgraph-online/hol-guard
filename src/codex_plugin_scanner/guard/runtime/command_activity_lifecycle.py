"""Pure construction of privacy-safe command activity lifecycle evidence."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime

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
