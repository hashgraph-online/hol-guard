"""Translate the resident's persistence answer for the callers that save a decision.

The resident decides both gates: whether a remembered decision is one this
request can be bound to, and whether an allow has any way of reaching an
execution. This module only turns that answer into the exceptions those
callers already handle, so nothing is saved here that the request does not
support. It lives apart from the scope-selection helpers so that the two
resolutions stay separately readable.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import cast

from .approval_scope_support import (
    IneligibleApprovalScopeError,
    ResolutionAction,
    StaleApprovalScopeContractError,
    _contract_from_native,
    _scope_item,
)


def resolve_request_persistence_selection(
    request: Mapping[str, object],
    *,
    action: str,
    applied_scope: str,
    persist_policy: bool | None,
    scope_narrowed: bool,
    contract_version: str | None,
    contract_digest: str | None,
    guard_home: Path | None = None,
) -> bool | None:
    """Ask the resident whether this resolution may be saved, and may run.

    The resident derives the contract itself and decides both gates together:
    whether a remembered decision is one this request can be bound to, and
    whether an allow has any way of reaching an execution. This function only
    translates that answer into the exceptions its callers already handle, so
    nothing is saved here that the request does not support.
    """

    # Imported here so a test can stand in for the resident bridge, and so the
    # adapter is loaded only on the path that actually calls it.
    from .native_approval_persist_select import native_approval_persist_selection
    from .native_approval_scope import ApprovalScopeUnavailableError

    answer = native_approval_persist_selection(
        _scope_item(request),
        action=action,
        applied_scope=applied_scope,
        persist_policy=persist_policy,
        scope_narrowed=scope_narrowed,
        contract_version=contract_version,
        contract_digest=contract_digest,
        guard_home=guard_home,
    )
    native_contract = answer.get("contract")
    contract = _contract_from_native(native_contract) if isinstance(native_contract, Mapping) else None
    outcome = answer.get("outcome")
    if outcome == "selected":
        selected = answer.get("persist_policy")
        if not (selected is None or isinstance(selected, bool)):
            raise ApprovalScopeUnavailableError
        return selected
    if outcome != "refused":
        raise ApprovalScopeUnavailableError
    reason = answer.get("reason")
    if reason == "unsupported_resolution_action":
        raise ValueError("unsupported_resolution_action")
    if reason == "unsupported_approval_scope":
        raise ValueError(f"Unsupported approval scope: {applied_scope}")
    # Every remaining refusal reports what the request does offer, so a caller
    # that cannot see the contract has nothing to tell the user.
    if contract is None:
        raise ApprovalScopeUnavailableError
    if reason == "incomplete_scope_contract":
        raise ValueError("incomplete_scope_contract")
    if reason == "stale_scope_contract":
        raise StaleApprovalScopeContractError(contract)
    if reason in (
        "saved_allow_scope_ineligible",
        "saved_block_scope_ineligible",
        "execution_binding_unavailable",
    ):
        raise IneligibleApprovalScopeError(
            reason,
            contract,
            action=cast(ResolutionAction, "allow" if action == "allow" else "block"),
            requested_scope=applied_scope,
        )
    raise ApprovalScopeUnavailableError
