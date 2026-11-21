"""Resolve a chosen approval scope, and whether to remember it, in the resident.

Only the approval center, the dashboard's request-resolution route and the
exact Cloud Review apply path resolve a selection; no hook admission reaches
this module.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Final, cast

from .approval_scope_support import (
    ApprovalScopeContract,
    IneligibleApprovalScopeError,
    ResolutionAction,
    StaleApprovalScopeContractError,
    _contract_from_native,
    _decision_scope,
    _scope_item,
)
from .models import DECISION_SCOPE_VALUES, DecisionScope

_INELIGIBLE_REASONS: Final = (
    "ineligible_request_scope",
    "request_action_not_overridable",
    "saved_allow_scope_ineligible",
    "saved_block_scope_ineligible",
    "execution_binding_unavailable",
)


@dataclass(frozen=True, slots=True)
class ApprovalScopeSelection:
    requested_scope: DecisionScope
    applied_scope: DecisionScope
    warning: str | None = None
    contract: ApprovalScopeContract | None = None
    exact_token: str | None = None
    persist_policy: bool | None = None


def resolve_request_scope_selection(
    request: Mapping[str, object],
    *,
    action: str,
    requested_scope: str,
    contract_version: str | None,
    contract_digest: str | None,
    persist_policy: object = None,
    ask_persistence: bool = False,
    guard_home: Path | None = None,
) -> ApprovalScopeSelection:
    """Ask the resident what a chosen approval scope actually resolves to.

    The resident derives the contract itself and decides whether the chosen
    scope is one the request offers for this action, whether a client that
    never read a contract has its wider choice narrowed to the artifact, and
    whether a client resolving against a superseded contract is refused. With
    ``ask_persistence`` the same answer also decides whether ``persist_policy``
    is honoured at the applied scope and whether an allow can reach an
    execution. This function only translates that answer into the exceptions
    its callers already handle, so no scope can be honoured here that the
    request does not offer.
    """

    from .native_approval_scope import ApprovalScopeUnavailableError
    from .native_approval_scope_select import PERSIST_NOT_ASKED, native_approval_scope_selection

    answer = native_approval_scope_selection(
        _scope_item(request),
        action=action,
        requested_scope=requested_scope,
        contract_version=contract_version,
        contract_digest=contract_digest,
        persist_policy=persist_policy if ask_persistence else PERSIST_NOT_ASKED,
        guard_home=guard_home,
    )
    native_contract = answer.get("contract")
    contract = _contract_from_native(native_contract) if isinstance(native_contract, Mapping) else None
    outcome = answer.get("outcome")
    if outcome == "selected":
        applied_scope = answer.get("applied_scope")
        warning = answer.get("warning")
        selected_persist = answer.get("persist_policy")
        exact_token = native_contract.get("exact_context_token") if isinstance(native_contract, Mapping) else None
        if (
            not isinstance(applied_scope, str)
            or applied_scope not in DECISION_SCOPE_VALUES
            or not (warning is None or isinstance(warning, str))
            or not (selected_persist is None or isinstance(selected_persist, bool))
            or (ask_persistence and "persist_policy" not in answer)
            or not (exact_token is None or isinstance(exact_token, str))
            or (ask_persistence and contract is None)
        ):
            raise ApprovalScopeUnavailableError
        return ApprovalScopeSelection(
            requested_scope=_decision_scope(requested_scope),
            applied_scope=_decision_scope(applied_scope),
            warning=warning,
            contract=contract,
            exact_token=exact_token,
            persist_policy=selected_persist,
        )
    if outcome != "refused":
        raise ApprovalScopeUnavailableError
    reason = answer.get("reason")
    if reason == "unsupported_resolution_action":
        raise ValueError("unsupported_resolution_action")
    if reason == "unsupported_approval_scope":
        raise ValueError(f"Unsupported approval scope: {requested_scope}")
    # Every remaining refusal reports what the request does offer, so a caller
    # that cannot see the contract has nothing to tell the user.
    if contract is None:
        raise ApprovalScopeUnavailableError
    if reason == "incomplete_scope_contract":
        raise ValueError("incomplete_scope_contract")
    if reason == "stale_scope_contract":
        raise StaleApprovalScopeContractError(contract)
    # A persistence refusal comes after the scope was applied, and names it.
    if reason in _INELIGIBLE_REASONS:
        raise IneligibleApprovalScopeError(
            reason,
            contract,
            action=cast(ResolutionAction, action),
            requested_scope=str(answer.get("applied_scope") or requested_scope),
        )
    raise ApprovalScopeUnavailableError
