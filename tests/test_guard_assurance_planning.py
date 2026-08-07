"""Tests for assurance planning factors in the effect decision engine."""

from __future__ import annotations

from typing import cast

import pytest

from codex_plugin_scanner.guard.action_lattice import guard_action_severity
from codex_plugin_scanner.guard.runtime.assurance_planning import (
    AssurancePlan,
    AssuranceRequirement,
    assurance_factor,
    simulate_assurance_plan,
)
from codex_plugin_scanner.guard.runtime.effect_contract import DecisionBasis
from codex_plugin_scanner.guard.runtime.effect_decision import (
    DecisionFactor,
    DecisionFactorSource,
    EffectDecisionRequest,
    evaluate_effect_decision,
)
from codex_plugin_scanner.guard.runtime.execution_assurance_contract import (
    AtomicGuarantee,
    AtomicGuaranteeKind,
    DecisionContext,
    GuardExecutionAssuranceBoundary,
)

_SHA = "a" * 64
_OTHER = "b" * 64


def _guarantee(
    kind: AtomicGuaranteeKind,
    *,
    enforced: bool = True,
    boundary: GuardExecutionAssuranceBoundary = GuardExecutionAssuranceBoundary.OS_ISOLATED,
) -> AtomicGuarantee:
    return AtomicGuarantee(kind=kind, enforced=enforced, boundary=boundary)


def _requirement(
    *,
    boundary: GuardExecutionAssuranceBoundary = GuardExecutionAssuranceBoundary.OS_ISOLATED,
    guarantees: tuple[AtomicGuaranteeKind, ...] = (AtomicGuaranteeKind.FILESYSTEM,),
) -> AssuranceRequirement:
    return AssuranceRequirement(minimum_boundary=boundary, required_guarantees=guarantees)


def _plan(guarantees: tuple[AtomicGuarantee, ...]) -> AssurancePlan:
    return AssurancePlan(
        boundary=GuardExecutionAssuranceBoundary.OS_ISOLATED,
        available_guarantees=guarantees,
    )


class TestAssuranceFactor:
    def test_satisfied_requirement_adds_no_high_floor(self) -> None:
        factor = assurance_factor(_requirement(), _plan((_guarantee(AtomicGuaranteeKind.FILESYSTEM),)))
        assert factor.source is DecisionFactorSource.ASSURANCE
        assert factor.basis.action_floor == "warn"

    def test_unmet_requirement_raises_to_sandbox(self) -> None:
        # Requirement demands network guarantee; plan enforces only filesystem.
        factor = assurance_factor(_requirement(), _plan(()))
        assert factor.basis.action_floor == "sandbox-required"
        assert factor.reason_code.endswith(".unmet")

    def test_weak_boundary_never_substitutes_for_missing_guarantee(self) -> None:
        # Even hardware isolated, missing required guarantee still unsatisfied.
        strong = _guarantee(AtomicGuaranteeKind.FILESYSTEM, boundary=GuardExecutionAssuranceBoundary.HARDWARE_ISOLATED)
        factor = assurance_factor(
            _requirement(guarantees=(AtomicGuaranteeKind.NETWORK,)),
            _plan((strong,)),
        )
        assert guard_action_severity(factor.basis.action_floor) >= guard_action_severity("sandbox-required")


class TestMonotonicityAndNonInterference:
    def _blocked_factor(self) -> DecisionFactor:
        return DecisionFactor(
            source=DecisionFactorSource.POLICY,
            reason_code="policy.block",
            basis=DecisionBasis(action_floor="block", proof_route=None),
        )

    def test_assurance_never_lowers_blocked_floor(self) -> None:
        # No provider auto-approval: a block stays block at every assurance level.
        assurance = assurance_factor(_requirement(), _plan((_guarantee(AtomicGuaranteeKind.FILESYSTEM),)))
        decision = evaluate_effect_decision(EffectDecisionRequest(factors=(self._blocked_factor(), assurance)))
        assert decision.action == "block"

    def test_assurance_never_lowers_review_floor(self) -> None:
        review = DecisionFactor(
            source=DecisionFactorSource.POLICY,
            reason_code="policy.review",
            basis=DecisionBasis(action_floor="review", proof_route=None),
        )
        assurance = assurance_factor(_requirement(), _plan((_guarantee(AtomicGuaranteeKind.FILESYSTEM),)))
        decision = evaluate_effect_decision(EffectDecisionRequest(factors=(review, assurance)))
        assert guard_action_severity(decision.action) >= guard_action_severity("review")

    def test_assurance_only_raises(self) -> None:
        base = DecisionFactor(
            source=DecisionFactorSource.POLICY,
            reason_code="policy.review",
            basis=DecisionBasis(action_floor="review", proof_route=None),
        )
        low = assurance_factor(_requirement(), _plan((_guarantee(AtomicGuaranteeKind.FILESYSTEM),)))
        high = assurance_factor(_requirement(), _plan(()))
        assert guard_action_severity(
            evaluate_effect_decision(EffectDecisionRequest(factors=(base, high))).action
        ) >= guard_action_severity(evaluate_effect_decision(EffectDecisionRequest(factors=(base, low))).action)


class TestDeterminism:
    def test_repeated_evaluation_identical(self) -> None:
        factor = assurance_factor(_requirement(), _plan((_guarantee(AtomicGuaranteeKind.FILESYSTEM),)))
        first = simulate_assurance_plan(_requirement(), _plan((_guarantee(AtomicGuaranteeKind.FILESYSTEM),)))
        second = simulate_assurance_plan(_requirement(), _plan((_guarantee(AtomicGuaranteeKind.FILESYSTEM),)))
        assert first == second
        assert factor == assurance_factor(_requirement(), _plan((_guarantee(AtomicGuaranteeKind.FILESYSTEM),)))

    def test_simulation_is_side_effect_free_and_context_optional(self) -> None:
        ctx = DecisionContext(
            repository_digest=_SHA,
            workspace_digest=_OTHER,
            executable_digest=_SHA,
            action_class="package-install",
        )
        with_ctx = simulate_assurance_plan(_requirement(), _plan(()), context=ctx)
        without_ctx = simulate_assurance_plan(_requirement(), _plan(()))
        assert without_ctx["satisfied"] is False
        assert with_ctx["context_digest"] == ctx.context_digest
        assert "context_digest" not in without_ctx


class TestValidation:
    def test_factor_rejects_non_requirement(self) -> None:
        with pytest.raises(ValueError, match="AssuranceRequirement"):
            assurance_factor(cast(AssuranceRequirement, object()), _plan(()))

    def test_factor_rejects_non_plan(self) -> None:
        with pytest.raises(ValueError, match="AssurancePlan"):
            assurance_factor(_requirement(), cast(AssurancePlan, object()))
