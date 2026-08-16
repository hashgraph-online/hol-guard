"""Assurance planning factors for the effect decision engine (pure, monotonic).

Extends the existing monotonic effect decision with execution-assurance
requirements and plans. This is a single ``DecisionFactorSource.ASSURANCE``
extension to :func:`evaluate_effect_decision`: it only raises action floors,
never lowers them, so a blocked/review-required action stays blocked/review at
every assurance level (no provider auto-approval), and it adds no second
resolver or action lattice. ``simulate_assurance_plan`` is side-effect-free.

Central policy authority is preserved: assurance factors are lower bounds
composed under the same maximum-floor rule as every other factor.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from codex_plugin_scanner.guard.action_lattice import guard_action_severity
from codex_plugin_scanner.guard.models import GuardAction
from codex_plugin_scanner.guard.runtime.effect_contract import DecisionBasis, ProofRequirement, ProofRoute
from codex_plugin_scanner.guard.runtime.effect_decision import (
    DecisionFactor,
    DecisionFactorSource,
    PositiveProof,
)
from codex_plugin_scanner.guard.runtime.execution_assurance_contract import (
    AtomicGuarantee,
    AtomicGuaranteeKind,
    DecisionContext,
    GuardExecutionAssuranceBoundary,
    framed_digest,
    require_guarantees_satisfied,
)

# Boundary strength maps onto the canonical action lattice. A required boundary
# that available guarantees cannot satisfy raises the floor; it never lowers it.
_BOUNDARY_FLOOR: Final[dict[GuardExecutionAssuranceBoundary, GuardAction]] = {
    GuardExecutionAssuranceBoundary.OBSERVED_HOST: "warn",
    GuardExecutionAssuranceBoundary.CONTROLLED_HOST: "review",
    GuardExecutionAssuranceBoundary.OS_ISOLATED: "sandbox-required",
    GuardExecutionAssuranceBoundary.HARDWARE_ISOLATED: "sandbox-required",
}


@dataclass(frozen=True, slots=True)
class AssuranceRequirement:
    """A required assurance boundary and atomic guarantee set for a decision."""

    minimum_boundary: GuardExecutionAssuranceBoundary
    required_guarantees: tuple[AtomicGuaranteeKind, ...]
    reason_code: str = "assurance.requirement"


@dataclass(frozen=True, slots=True)
class AssurancePlan:
    """A planned containment route. Pure data; no provider, no execution."""

    boundary: GuardExecutionAssuranceBoundary
    available_guarantees: tuple[AtomicGuarantee, ...]
    reason_code: str = "assurance.plan"


def _require_assurance_requirement(value: object) -> None:
    if not isinstance(value, AssuranceRequirement):
        raise ValueError("requirement must be an AssuranceRequirement")


def _require_assurance_plan(value: object) -> None:
    if not isinstance(value, AssurancePlan):
        raise ValueError("plan must be an AssurancePlan")


def assurance_factor(requirement: AssuranceRequirement, plan: AssurancePlan) -> DecisionFactor:
    """Compose one assurance factor as a lower bound on the final action.

    If the plan's enforced guarantees satisfy the requirement at or above the
    required boundary, the requirement adds no floor. If they cannot, the floor
    rises to the boundary's mapped action so the shortfall is enforced, never
    papered over by a label.
    """

    _require_assurance_requirement(requirement)
    _require_assurance_plan(plan)
    unsatisfied = require_guarantees_satisfied(
        requirement.required_guarantees,
        plan.available_guarantees,
        requirement.minimum_boundary,
    )
    boundary_floor = _BOUNDARY_FLOOR[requirement.minimum_boundary]
    if unsatisfied:
        floor = (
            "sandbox-required"
            if guard_action_severity("sandbox-required") >= guard_action_severity(boundary_floor)
            else boundary_floor
        )
        reason_code = f"{requirement.reason_code}.unmet"
        return DecisionFactor(
            source=DecisionFactorSource.ASSURANCE,
            reason_code=reason_code,
            basis=DecisionBasis(action_floor=floor, proof_route=None),
        )
    # Satisfied assurance binds a verified positive proof at the warn floor; a
    # permissive floor requires proof on the exact route by the invariant.
    binding_digest = framed_digest(
        "guard.assurance-plan.v1",
        {
            "boundary": requirement.minimum_boundary.value,
            "required_guarantees": [kind.value for kind in requirement.required_guarantees],
            "plan_boundary": plan.boundary.value,
        },
    )
    return DecisionFactor(
        source=DecisionFactorSource.ASSURANCE,
        reason_code=requirement.reason_code,
        basis=DecisionBasis(action_floor="warn", proof_route=ProofRoute.VERIFIED),
        proof=PositiveProof(
            route=ProofRoute.VERIFIED,
            binding_digest=binding_digest,
            satisfied_requirements=frozenset({ProofRequirement.CONTAINMENT_IDENTITY}),
        ),
    )


def simulate_assurance_plan(
    requirement: AssuranceRequirement,
    plan: AssurancePlan,
    *,
    context: DecisionContext | None = None,
) -> dict[str, object]:
    """Return a pure, side-effect-free plan evaluation summary.

    Performs no I/O, spawns nothing, and never invokes a provider. ``context``
    is optional digest-bound correlation only and is never required.
    """

    factor = assurance_factor(requirement, plan)
    unsatisfied = require_guarantees_satisfied(
        requirement.required_guarantees,
        plan.available_guarantees,
        requirement.minimum_boundary,
    )
    summary: dict[str, object] = {
        "boundary": requirement.minimum_boundary.value,
        "satisfied": not unsatisfied,
        "unsatisfied_guarantees": list(unsatisfied),
        "resulting_floor": factor.basis.action_floor,
    }
    if context is not None:
        summary["context_digest"] = context.context_digest
    return summary


__all__ = [
    "AssurancePlan",
    "AssuranceRequirement",
    "assurance_factor",
    "simulate_assurance_plan",
]
