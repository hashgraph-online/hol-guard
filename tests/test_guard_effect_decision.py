from __future__ import annotations

import itertools
from dataclasses import replace
from typing import cast

import pytest

from codex_plugin_scanner.guard.action_lattice import GUARD_ACTION_LATTICE, GUARD_ACTION_SEVERITY
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
    EffectDecisionRequest,
    FinalDisposition,
    PositiveProof,
    evaluate_effect_decision,
    factors_from_extension_evidence,
)
from codex_plugin_scanner.guard.runtime.extension_evidence import (
    EvidenceSeverity,
    ExtensionEvidence,
    ExtensionEvidenceBatch,
    ExtensionMatchClass,
    ExtensionRuleIdentity,
    OwnedSafeVariant,
    SafeVariantOutcome,
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


def test_truth_table_uses_the_canonical_maximum_for_every_pair() -> None:
    for left, right in itertools.product(GUARD_ACTION_LATTICE, repeat=2):
        left_route = ProofRoute.VERIFIED if GUARD_ACTION_SEVERITY[left] < GUARD_ACTION_SEVERITY["review"] else None
        right_route = ProofRoute.VERIFIED if GUARD_ACTION_SEVERITY[right] < GUARD_ACTION_SEVERITY["review"] else None
        decision = evaluate_effect_decision(
            EffectDecisionRequest(
                (
                    _factor(left, "left", segment="segment:0", route=left_route),
                    _factor(right, "right", segment="segment:1", route=right_route),
                )
            )
        )
        assert GUARD_ACTION_SEVERITY[decision.action] == max(GUARD_ACTION_SEVERITY[left], GUARD_ACTION_SEVERITY[right])


def test_all_segment_all_effect_composition_is_permutation_independent() -> None:
    factors = (
        _factor("allow", "read.proven", segment="segment:0", route=ProofRoute.VERIFIED),
        _factor("review", "remote.mutation", segment="segment:1"),
        _factor("block", "guard.tamper", segment="segment:2"),
    )
    decisions = {evaluate_effect_decision(EffectDecisionRequest(order)) for order in itertools.permutations(factors)}
    assert len(decisions) == 1
    decision = decisions.pop()
    assert decision.action == "block"
    assert [reason.reason_code for reason in decision.controlling_reasons] == ["guard.tamper"]


@pytest.mark.parametrize(
    ("route", "disposition"),
    [
        (ProofRoute.VERIFIED, FinalDisposition.SILENT_VERIFIED),
        (ProofRoute.CONTAINED, FinalDisposition.SILENT_CONTAINED),
        (ProofRoute.WORKFLOW_AUTHORIZED, FinalDisposition.WORKFLOW_AUTHORIZED),
    ],
)
def test_silent_dispositions_require_exact_positive_proof(route: ProofRoute, disposition: FinalDisposition) -> None:
    factor = _factor("allow", "bounded.operation", segment="segment:0", route=route)
    assert evaluate_effect_decision(EffectDecisionRequest((factor,))).disposition is disposition
    with pytest.raises(ValueError, match="exact route"):
        _ = replace(factor, proof=None)


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


def test_distinct_same_kind_assessments_retain_lossless_identity() -> None:
    workspace = _factor(
        "allow",
        "process.contained",
        segment="segment:0",
        route=ProofRoute.CONTAINED,
        assessment=_assessment(),
    )
    external = replace(
        workspace,
        assessment=replace(_assessment(), target_scope=EffectTargetScope.EXTERNAL_LOCAL),
    )
    request = EffectDecisionRequest((workspace, external))
    assert len(request.factors) == 2
    assert evaluate_effect_decision(request).action == "allow"


def test_effect_and_global_uncertainty_can_only_raise_the_result() -> None:
    factor = _factor(
        "allow",
        "process.contained",
        segment="segment:0",
        route=ProofRoute.CONTAINED,
        assessment=_assessment(uncertainty_reasons=(UncertaintyKind.PARTIAL_PARSE,)),
    )
    decision = evaluate_effect_decision(EffectDecisionRequest((factor,), (UncertaintyKind.PARSER_FAILURE,)))
    assert decision.action == "block"
    assert decision.disposition is FinalDisposition.BLOCK
    assert {reason.reason_code for reason in decision.reasons} >= {
        "uncertainty.partial-parse",
        "uncertainty.parser-failure",
    }


def test_empty_or_malformed_input_fails_closed() -> None:
    assert evaluate_effect_decision(EffectDecisionRequest(())).action == "review"
    with pytest.raises(ValueError, match="DecisionFactor"):
        _ = EffectDecisionRequest(cast(tuple[DecisionFactor, ...], (object(),)))
    with pytest.raises(ValueError, match="schema version"):
        _ = EffectDecisionRequest((), schema_version="2.0.0")
    with pytest.raises(ValueError, match="lowercase SHA-256"):
        _ = replace(_proof(), binding_digest="not-a-digest")


def _evidence(
    rule_suffix: str,
    floor: GuardAction,
    *,
    safe: bool = False,
) -> ExtensionEvidence:
    identity = ExtensionRuleIdentity("command.test", "1.0.0", f"command.test.{rule_suffix}", "1.0.0")
    return ExtensionEvidence(
        identity=identity,
        match_class=ExtensionMatchClass.UNSAFE,
        severity=EvidenceSeverity.CRITICAL if floor == "block" else EvidenceSeverity.HIGH,
        declared_floor=floor,
        base_fact=f"{rule_suffix}.matched",
        segment_ref=f"segment:{rule_suffix}",
        operation_ref=f"operation:{rule_suffix}",
        effect_claims=frozenset({EffectKind.DESTRUCTIVE_OR_IRREVERSIBLE_OPERATION}),
        proof_requirements=frozenset({ProofRequirement.OPERATION_AND_TARGETS}),
        safe_variant=(
            OwnedSafeVariant(identity, f"{rule_suffix}.safe", SafeVariantOutcome.OWNED_RULE_NOT_RAISED)
            if safe
            else None
        ),
    )


def test_owned_safe_variant_never_suppresses_a_stronger_sibling() -> None:
    safe = _evidence("owned", "review", safe=True)
    sibling = _evidence("sibling", "block")
    factors = factors_from_extension_evidence(ExtensionEvidenceBatch((safe, sibling)))
    decision = evaluate_effect_decision(EffectDecisionRequest(factors))
    assert [factor.reason_code for factor in factors] == ["sibling.matched"]
    assert decision.action == "block"


def test_extension_factor_identity_binds_the_complete_evidence_record() -> None:
    first = _evidence("shared", "review")
    second = replace(first, severity=EvidenceSeverity.CRITICAL)
    factors = factors_from_extension_evidence(ExtensionEvidenceBatch((first, second)))
    assert len({factor.evidence_digest for factor in factors}) == 2
    assert evaluate_effect_decision(EffectDecisionRequest(factors)).action == "review"
