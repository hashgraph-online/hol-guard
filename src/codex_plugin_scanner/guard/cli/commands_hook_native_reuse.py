"""Guard CLI artifact hook approval reuse: the facts it asks from, and the effects it runs.

The resident walks the saved-approval reuse ladder (``artifact_reuse_step``) and
answers a plan. This module gathers the facts that plan is decided from, runs
the plan's effects (the store claim and the revalidation after it) and holds no
branch of its own, with one exception: a package request whose resident cannot
plan its reuse falls to ``package_reuse_floor``, which never ends weaker than the
recomputed action and never lets a claimed approval skip its revalidation.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Callable, Mapping, Sequence
from typing import Any, TypeVar

from ..action_lattice import most_restrictive_guard_action
from ..models import GuardArtifact
from ..native_github_workflow import GitHubWorkflowDescriptor
from ..native_hook_artifact_reuse_step import (
    ReuseClaim,
    ReusePlan,
    ReuseRevalidate,
    ReuseSettled,
)
from ..native_hook_decision import _INVALID, NativeHookDecisionError
from ..runtime.approval_context import approval_context_tokens_validation_reason
from ..runtime.approval_reuse import approval_reuse_authority_unavailable
from ..runtime.github_workflow_runtime import resolved_github_workflow_capability_preflight
from .commands_hook_github_workflow import claimed_approval_request_id
from .commands_support_runtime_artifacts import _optional_string
from .commands_support_runtime_policy import _runtime_saved_allow_validation_reason

_SAVED_KEYS = (
    "stored_present",
    "stored_action",
    "stored_artifact_hash",
    "integrity_failure",
    "stored_validation_reason",
    "cursor_native_present",
    "cursor_validation_reason",
    "diagnostic_reason",
    "diagnostic_stored_hash",
)
_Outcome = TypeVar("_Outcome")


def _stored_row(decision: Mapping[str, object] | None) -> dict[str, object] | None:
    """The saved decision, reduced to what reuse reads."""

    if decision is None:
        return None
    return {
        "action": decision.get("action"),
        "artifact_hash": decision.get("artifact_hash"),
        "source": decision.get("source"),
        "request_id": claimed_approval_request_id(decision),
    }


def _workflow_preflight(store: Any, request_id: str, descriptor: GitHubWorkflowDescriptor) -> bool:
    """Whether the request's workflow capability is pending, from read-only store lookups.

    The resident reads this only when a saved allow asks to be approved again,
    but it is gathered before the resident is asked. A store that cannot be
    read is a capability that is not pending, the preflight's own answer for
    every lookup it cannot verify, so a request that never needed it is not
    failed by it and one that did is asked again.
    """

    try:
        return bool(resolved_github_workflow_capability_preflight(store, request_id, descriptor))
    except sqlite3.Error:
        return False


def _tool_lookup(
    saved_reuse: Mapping[str, object] | None,
    *,
    workflow_preflight: bool,
) -> dict[str, object]:
    """A tool request's saved lookup: the facts the store's own query gathered, less the action.

    The resident asks the same query of itself, so a store that built none (or
    an incomplete one) leaves nothing to settle the reuse from.
    """

    query = saved_reuse.get("query") if saved_reuse is not None else None
    if not isinstance(query, Mapping) or any(key not in query for key in _SAVED_KEYS):
        raise NativeHookDecisionError(_INVALID)
    return {
        "mode": "tool",
        "saved": {key: query[key] for key in _SAVED_KEYS},
        "workflow_preflight": workflow_preflight,
    }


def reuse_step_facts(
    *,
    store: Any,
    artifact: GuardArtifact,
    artifact_hash: str,
    current_action: str,
    claim_saved_approval: bool,
    remembered_rule_rejected: bool,
    stored_decision: Mapping[str, object] | None,
    saved_reuse: Mapping[str, object] | None,
    package_reasons: Sequence[Mapping[str, object]] | None,
    package_policy_action: str | None,
    workflow_descriptor: GitHubWorkflowDescriptor | None,
    trusted_override_hash: str | None,
    claimed_hash: str | None,
    post_claim_refresh_failed: bool,
    workflow_capability_required: bool,
    workflow_authorization_claimed: bool,
    claimed_trusted_request_override: bool,
    claimed_package_approval_consumed: bool,
) -> dict[str, object]:
    """Everything the resident needs to plan the reuse of a saved approval.

    ``package_reasons`` is ``None`` for a tool request and a package request's
    evaluation reasons otherwise. Every field travels explicitly, nulls
    included, so the reply binds to the digest of the request as decoded.
    """

    stored = _stored_row(stored_decision)
    if package_reasons is not None:
        lookup: dict[str, object] = {
            "mode": "package",
            "reasons": [dict(reason) for reason in package_reasons],
            "evaluation_policy_action": package_policy_action,
        }
    else:
        request_id = stored["request_id"] if stored is not None else None
        lookup = _tool_lookup(
            saved_reuse,
            workflow_preflight=bool(
                workflow_descriptor is not None
                and request_id is not None
                and _workflow_preflight(store, str(request_id), workflow_descriptor)
            ),
        )
    return {
        "claim_saved_approval": bool(claim_saved_approval),
        "current_action": current_action,
        "remembered_rule_rejected": remembered_rule_rejected,
        "stored": stored,
        "lookup": lookup,
        "trusted_override": (
            None
            if trusted_override_hash is None
            else {
                "token_validation_reason": approval_context_tokens_validation_reason(
                    trusted_override_hash,
                    artifact_hash,
                ),
                "stored_validation_reason": (
                    _runtime_saved_allow_validation_reason(
                        stored_decision, artifact=artifact, artifact_hash=artifact_hash
                    )
                    if stored_decision is not None
                    else None
                ),
            }
        ),
        "claimed": (
            None
            if claimed_hash is None
            else {
                "claimed_hash": claimed_hash,
                "token_validation_reason": approval_context_tokens_validation_reason(claimed_hash, artifact_hash),
                "post_claim_refresh_failed": post_claim_refresh_failed,
                "workflow_capability_required": workflow_capability_required,
                "workflow_authorization_claimed": workflow_authorization_claimed,
                "claimed_trusted_request_override": claimed_trusted_request_override,
                "claimed_package_approval_consumed": claimed_package_approval_consumed,
            }
        ),
    }


def claim_saved_decision(store: Any, decision: Mapping[str, object] | None, *, now: str) -> bool:
    """Claim the saved approval in the store; a plan only claims what it was given."""

    if decision is None:
        raise NativeHookDecisionError(_INVALID)
    return bool(store.claim_approval_reuse_decision(decision, now=now))


def execute_reuse_plan(
    plan: ReusePlan,
    *,
    claim: Callable[[], bool],
    revalidate: Callable[[ReuseRevalidate], _Outcome],
) -> ReuseSettled | _Outcome:
    """Run a plan's effects: each claim takes the branch its outcome names.

    A claim that wins is followed by the revalidation and nothing else, with no
    resident round trip between consuming the approval and acting on it.
    """

    node = plan
    while isinstance(node, ReuseClaim):
        node = node.on_claimed if claim() else node.on_failed
    if isinstance(node, ReuseRevalidate):
        return revalidate(node)
    return node


def package_reuse_floor(
    facts: Mapping[str, Any],
    *,
    claimed_disposition: str | None,
) -> ReusePlan | None:
    """A package request's reuse when the resident cannot plan it.

    Nothing in the evaluation's reasons is read as reuse, so no saved approval
    or block is applied and none is claimed as a source. A saved allow the
    resolver already claimed is still revalidated at the execution boundary (an
    unreachable resident must never turn a consumed approval into a silent
    allow), a stored block still holds, the authority-unavailable reuse is
    still recorded, and the action never ends weaker than the recomputed one.
    ``None`` when the request needs the resident for more than that (a trusted
    request override or a claimed pass): the caller fails closed.
    """

    if claimed_disposition is not None:
        return ReuseRevalidate(
            trusted_request_override=False,
            package_approval_consumed=claimed_disposition == "consumed",
            request_id=None,
        )
    if facts["trusted_override"] is not None or facts["claimed"] is not None:
        return None
    current_action = facts["current_action"]
    stored = facts["stored"]
    stored_block = stored is not None and _optional_string(stored["action"]) == "block"
    reuse = approval_reuse_authority_unavailable(current_action) if stored_block else None
    policy_action = most_restrictive_guard_action(
        current_action,
        *([reuse.action] if reuse is not None else []),
        *(["block"] if stored_block else []),
    )
    evidence = reuse.to_evidence() if reuse is not None else None
    return ReuseSettled(
        policy_action=policy_action,
        approval_reuse_source=None,
        trusted_request_override_applied=False,
        trusted_request_override_reason=None,
        evidence=(
            ({"source": "approval_reuse", "input_source": "saved_policy_decision", **evidence},)
            if evidence is not None
            else ()
        ),
        approval_reuse=evidence,
        package_risk_refresh=policy_action != current_action,
    )
