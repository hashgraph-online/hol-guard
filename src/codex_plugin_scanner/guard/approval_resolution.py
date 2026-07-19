"""Canonical eligibility checks for resolving queued Guard approvals."""

from __future__ import annotations

from collections.abc import Mapping

from .action_lattice import normalize_guard_action_result
from .runtime.decisions import AUTHORITATIVE_DECISION_INCONSISTENT

TERMINAL_POLICY_ACTION_NOT_RESOLVABLE = "terminal_policy_action_not_resolvable"
_TERMINAL_POLICY_ACTIONS = frozenset({"block", "sandbox-required"})


def approval_resolution_block_reason(request: Mapping[str, object]) -> str | None:
    """Return why a canonical approval row cannot accept a user resolution."""

    if request.get("decision_contract_error") is not None:
        return AUTHORITATIVE_DECISION_INCONSISTENT
    normalization = normalize_guard_action_result(
        request.get("policy_action"),
        unknown_action="require-reapproval",
    )
    if not normalization.recognized:
        return AUTHORITATIVE_DECISION_INCONSISTENT
    if normalization.action in _TERMINAL_POLICY_ACTIONS:
        return TERMINAL_POLICY_ACTION_NOT_RESOLVABLE
    return None


def require_resolvable_approval_request(request: Mapping[str, object]) -> None:
    """Reject terminal or contract-invalid approval rows at mutation boundaries."""

    reason = approval_resolution_block_reason(request)
    if reason is not None:
        raise ValueError(reason)
