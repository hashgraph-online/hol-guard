from __future__ import annotations

from dataclasses import replace

import pytest

from codex_plugin_scanner.guard.models import GuardAction
from codex_plugin_scanner.guard.runtime.effect_contract import (
    ContainmentRequirement,
    DecisionBasis,
    EffectAssessment,
    EffectBlastRadius,
    EffectConfidence,
    EffectEvidenceSource,
    EffectKind,
    EffectReversibility,
    EffectTargetScope,
    ProofRequirement,
    ProofRoute,
    UncertaintyKind,
)
from codex_plugin_scanner.guard.runtime.effect_decision import (
    DecisionFactor,
    DecisionFactorSource,
    PositiveProof,
)

_DIGEST = "a" * 64


def _assessment(*, uncertainty_reasons: tuple[UncertaintyKind, ...] = ()) -> EffectAssessment:
    return EffectAssessment(
        kind=EffectKind.PROCESS_EXECUTION,
        target_scope=EffectTargetScope.WORKSPACE,
        reversibility=EffectReversibility.TRIVIALLY_RECOVERABLE,
        blast_radius=EffectBlastRadius.WORKSPACE,
        evidence_source=EffectEvidenceSource.LAUNCH_IDENTITY,
        confidence=EffectConfidence.EXACT if not uncertainty_reasons else EffectConfidence.PARTIAL,
        containment=ContainmentRequirement.REQUIRED,
        proof_requirements=frozenset({ProofRequirement.EXECUTABLE_IDENTITY, ProofRequirement.CONTAINMENT_IDENTITY}),
        uncertainty_reasons=uncertainty_reasons,
    )


def _proof(route: ProofRoute = ProofRoute.CONTAINED) -> PositiveProof:
    return PositiveProof(
        route=route,
        binding_digest=_DIGEST,
        satisfied_requirements=frozenset({ProofRequirement.EXECUTABLE_IDENTITY, ProofRequirement.CONTAINMENT_IDENTITY}),
        enforced=route is ProofRoute.CONTAINED,
    )


def _factor(
    floor: GuardAction,
    reason: str,
    *,
    segment: str,
    route: ProofRoute | None = None,
    assessment: EffectAssessment | None = None,
) -> DecisionFactor:
    return DecisionFactor(
        source=DecisionFactorSource.EFFECT if assessment is not None else DecisionFactorSource.POLICY,
        reason_code=reason,
        basis=DecisionBasis(floor, route),
        segment_ref=segment,
        operation_ref=f"operation:{segment.removeprefix('segment:')}",
        assessment=assessment,
        proof=_proof(route) if route is not None else None,
    )


def test_proof_binding_digest_must_be_lowercase_sha256() -> None:
    with pytest.raises(ValueError, match="lowercase SHA-256"):
        _ = replace(_proof(), binding_digest="not-a-digest")


def test_containment_must_be_enforced_and_bind_every_effect_requirement() -> None:
    with pytest.raises(ValueError, match="must be enforced"):
        _ = replace(_proof(), enforced=False)
    incomplete = PositiveProof(
        ProofRoute.VERIFIED,
        _DIGEST,
        frozenset({ProofRequirement.EXECUTABLE_IDENTITY}),
    )
    with pytest.raises(ValueError, match="every effect requirement"):
        _ = DecisionFactor(
            source=DecisionFactorSource.EFFECT,
            reason_code="process.proven",
            basis=DecisionBasis("allow", ProofRoute.VERIFIED),
            segment_ref="segment:0",
            operation_ref="operation:0",
            assessment=_assessment(),
            proof=incomplete,
        )


def test_containment_route_must_match_effect_eligibility() -> None:
    ineligible = replace(_assessment(), containment=ContainmentRequirement.NOT_ELIGIBLE)
    with pytest.raises(ValueError, match="incompatible"):
        _ = _factor(
            "allow",
            "process.contained",
            segment="segment:0",
            route=ProofRoute.CONTAINED,
            assessment=ineligible,
        )
    with pytest.raises(ValueError, match="require contained proof"):
        _ = _factor(
            "allow",
            "process.verified",
            segment="segment:0",
            route=ProofRoute.VERIFIED,
            assessment=_assessment(),
        )


def test_an_effect_factor_without_an_assessment_is_rejected() -> None:
    with pytest.raises(ValueError, match="effect factors require an assessment"):
        _ = DecisionFactor(
            source=DecisionFactorSource.EFFECT,
            reason_code="process.unassessed",
            basis=DecisionBasis("review", None),
            segment_ref="segment:0",
            operation_ref="operation:0",
        )


def test_a_permissive_basis_requires_proof_on_its_exact_route() -> None:
    with pytest.raises(ValueError, match="proof on the exact route"):
        _ = DecisionFactor(
            source=DecisionFactorSource.POLICY,
            reason_code="process.unproven",
            basis=DecisionBasis("allow", ProofRoute.VERIFIED),
            segment_ref="segment:0",
            operation_ref="operation:0",
        )
