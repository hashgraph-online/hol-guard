"""The artifact hook's approval-reuse state machine, answered by the native runtime.

The hook gathers what the store and the lookups hold. The resident walks the
whole reuse ladder (look up the saved approval, decide whether to claim it,
revalidate after a claim, let a trusted browser request override a review,
settle the claimed pass) and answers a *plan*: a tree of the effects the
transport runs. A ``claim`` node names the plan that follows each outcome of
the store claim, so the resident is not asked again between consuming an
approval and acting on it. There is no Python evaluator: a reply that is not a
bound, strictly decoded plan raises ``NativeHookDecisionError`` and the caller
fails closed.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .native_hook_decision import _INVALID, NativeHookDecisionError, _action, _decide, _shape
from .runtime.approval_reuse import ApprovalReuseMalformedResultError, _decision_from_native_payload

HOOK_DECISION_ARTIFACT_REUSE_STEP_FEATURE = "hook-decision-artifact-reuse-step-v1"
# The deepest a plan can nest: the saved claim, the override claim and the
# settlement behind both.
_MAX_DEPTH = 2
_INPUT_FIELDS = frozenset(
    {
        "claim_saved_approval",
        "current_action",
        "remembered_rule_rejected",
        "stored",
        "lookup",
        "trusted_override",
        "claimed",
    }
)
_REVALIDATE_FIELDS: dict[str, Any] = {
    "effect": str,
    "trusted_request_override": bool,
    "package_approval_consumed": bool,
    "request_id": (str, type(None)),
}
_SETTLED_FIELDS: dict[str, Any] = {
    "effect": str,
    "policy_action": str,
    "approval_reuse_source": (str, type(None)),
    "trusted_request_override_applied": bool,
    "trusted_request_override_reason": (str, type(None)),
    "evidence": list,
    "approval_reuse": (dict, type(None)),
    "package_risk_refresh": bool,
}


@dataclass(frozen=True, slots=True)
class ReuseRevalidate:
    """Re-evaluate the request as the claimed approval's execution."""

    trusted_request_override: bool
    package_approval_consumed: bool
    request_id: str | None


@dataclass(frozen=True, slots=True)
class ReuseSettled:
    """Reuse is settled; the rest of the hook reads this."""

    policy_action: str
    approval_reuse_source: str | None
    trusted_request_override_applied: bool
    trusted_request_override_reason: str | None
    evidence: tuple[dict[str, Any], ...]
    approval_reuse: dict[str, Any] | None
    package_risk_refresh: bool


@dataclass(frozen=True, slots=True)
class ReuseClaim:
    """Claim the saved approval in the store.

    A claim that wins is always followed by the revalidation; a claim that
    loses is followed by the already-settled answer for that case, which may
    itself claim (the trusted-request override's approval).
    """

    on_claimed: ReuseRevalidate
    on_failed: ReuseClaim | ReuseSettled


ReusePlan = ReuseClaim | ReuseRevalidate | ReuseSettled


def _reuse_evidence(value: object, *, decision: bool) -> dict[str, Any] | None:
    if value is None and not decision:
        return None
    try:
        if decision:
            _decision_from_native_payload(value)
    except ApprovalReuseMalformedResultError:
        raise NativeHookDecisionError(_INVALID) from None
    if not isinstance(value, dict):
        raise NativeHookDecisionError(_INVALID)
    return value


def _node(raw: object, *, decision: bool, depth: int) -> ReusePlan:
    """One validated plan node. ``decision``: its reuse evidence is a native decision."""

    if depth > _MAX_DEPTH or not isinstance(raw, dict):
        raise NativeHookDecisionError(_INVALID)
    effect = raw.get("effect")
    if effect == "claim":
        if set(raw) != {"effect", "on_claimed", "on_failed"}:
            raise NativeHookDecisionError(_INVALID)
        revalidate = _node(raw["on_claimed"], decision=decision, depth=depth + 1)
        failed = _node(raw["on_failed"], decision=decision, depth=depth + 1)
        if not isinstance(revalidate, ReuseRevalidate) or isinstance(failed, ReuseRevalidate):
            raise NativeHookDecisionError(_INVALID)
        return ReuseClaim(on_claimed=revalidate, on_failed=failed)
    if effect == "revalidate":
        fields = _shape(raw, _REVALIDATE_FIELDS)
        return ReuseRevalidate(
            trusted_request_override=fields["trusted_request_override"],
            package_approval_consumed=fields["package_approval_consumed"],
            request_id=fields["request_id"],
        )
    if effect != "settled":
        raise NativeHookDecisionError(_INVALID)
    settled = _shape(raw, _SETTLED_FIELDS)
    if not all(isinstance(entry, dict) for entry in settled["evidence"]):
        raise NativeHookDecisionError(_INVALID)
    return ReuseSettled(
        policy_action=_action(settled["policy_action"]),
        approval_reuse_source=settled["approval_reuse_source"],
        trusted_request_override_applied=settled["trusted_request_override_applied"],
        trusted_request_override_reason=settled["trusted_request_override_reason"],
        evidence=tuple(settled["evidence"]),
        approval_reuse=_reuse_evidence(settled["approval_reuse"], decision=decision),
        package_risk_refresh=settled["package_risk_refresh"],
    )


def native_artifact_reuse_step(inputs: Mapping[str, object], *, guard_home: Path | None = None) -> ReusePlan:
    """The effects to run for the artifact hook's approval reuse, as a plan.

    A tool request's settlement always carries a native reuse decision; a
    package request's may carry the package evaluation's own reuse evidence.
    """

    lookup = inputs.get("lookup")
    if set(inputs) != _INPUT_FIELDS or not isinstance(lookup, Mapping) or lookup.get("mode") not in {"tool", "package"}:
        raise NativeHookDecisionError(_INVALID)
    decision = lookup["mode"] == "tool"
    plans: list[ReusePlan] = []

    def validate(payload: dict[str, Any]) -> None:
        if set(payload) != {"kind", "plan"}:
            raise NativeHookDecisionError(_INVALID)
        plans.append(_node(payload["plan"], decision=decision, depth=0))

    _decide(
        {"kind": "artifact_reuse_step", "inputs": dict(inputs)},
        guard_home,
        validate,
        HOOK_DECISION_ARTIFACT_REUSE_STEP_FEATURE,
    )
    return plans[0]


__all__ = [
    "HOOK_DECISION_ARTIFACT_REUSE_STEP_FEATURE",
    "ReuseClaim",
    "ReusePlan",
    "ReuseRevalidate",
    "ReuseSettled",
    "native_artifact_reuse_step",
]
