"""Project a validated reuse result into the current tool-call decision."""

from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING

from .approval_reuse import (
    APPROVAL_REUSE_ACCEPTED,
    APPROVAL_REUSE_CURRENT_ACTION_UNKNOWN,
    APPROVAL_REUSE_NO_SAVED_DECISION,
    APPROVAL_REUSE_SAVED_ACTION_UNKNOWN,
    ApprovalReuseDecision,
)

if TYPE_CHECKING:
    from ..mcp_tool_calls import ApprovalReuseClaimDisposition, ToolCallDecision


def _tool_call_decision_with_reuse(
    current: ToolCallDecision,
    reuse: ApprovalReuseDecision,
    *,
    pending_decision: Mapping[str, object] | None = None,
    claim_disposition: ApprovalReuseClaimDisposition | None = None,
) -> ToolCallDecision:
    from ..mcp_tool_calls import ToolCallDecision

    normalization_reason_code = reuse.saved_normalization_reason_code or reuse.current_normalization_reason_code
    original_action = reuse.original_saved_action or reuse.original_current_action
    if reuse.reason_code == APPROVAL_REUSE_SAVED_ACTION_UNKNOWN:
        source = "policy-invalid"
        summary = "Local Guard found an unknown policy action in saved state and requires reapproval."
    elif reuse.reason_code == APPROVAL_REUSE_CURRENT_ACTION_UNKNOWN:
        source = "policy-invalid"
        summary = "Local Guard found an unknown current policy action and blocked the tool call."
    elif reuse.reason_code == APPROVAL_REUSE_ACCEPTED:
        source = "policy"
        summary = "Local Guard reused an exact saved approval for the current reviewable tool call."
    elif reuse.reason_code == APPROVAL_REUSE_NO_SAVED_DECISION:
        source = current.source
        summary = current.summary
    elif reuse.saved_action == "block":
        source = "policy"
        summary = "Local Guard kept this tool call blocked by saved policy."
    else:
        source = current.source
        summary = f"{current.summary} Saved approval was not reused ({reuse.reason_code})."
    return ToolCallDecision(
        action=reuse.action,
        source=source,
        signals=current.signals,
        summary=summary,
        risk_categories=current.risk_categories,
        normalization_reason_code=normalization_reason_code,
        original_action=original_action,
        approval_reuse_status=reuse.status,
        approval_reuse_reason_code=reuse.reason_code,
        current_action=reuse.current_action,
        saved_action=reuse.saved_action,
        pending_approval_reuse_decision=pending_decision,
        approval_reuse_claim_disposition=claim_disposition,
        policy_rule_identity=reuse.policy_rule_identity,
    )
