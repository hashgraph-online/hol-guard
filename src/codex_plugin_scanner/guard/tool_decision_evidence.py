"""Shared audit evidence projection for MCP tool decisions."""

from __future__ import annotations

from typing import TYPE_CHECKING

from .mcp_tool_calls import resolve_tool_call_policy_action

if TYPE_CHECKING:
    from .mcp_tool_calls import ToolCallDecision


def tool_decision_scanner_evidence(decision: ToolCallDecision) -> tuple[dict[str, object], ...]:
    """Project normalization and approval-reuse evidence without payload data."""

    evidence: list[dict[str, object]] = []
    policy_action = resolve_tool_call_policy_action(decision)
    if decision.normalization_reason_code is not None:
        evidence.append(
            {
                "source": "guard_action_normalizer",
                "input_source": "stored_tool_policy",
                "reason_code": decision.normalization_reason_code,
                "original_action": decision.original_action,
                "normalized_action": policy_action,
            }
        )
    if decision.approval_reuse_reason_code is not None:
        evidence.append(
            {
                "source": "approval_reuse",
                "status": decision.approval_reuse_status,
                "reason_code": decision.approval_reuse_reason_code,
                "current_action": decision.current_action,
                "saved_action": decision.saved_action,
                "effective_action": policy_action,
            }
        )
    return tuple(evidence)


__all__ = ["tool_decision_scanner_evidence"]
