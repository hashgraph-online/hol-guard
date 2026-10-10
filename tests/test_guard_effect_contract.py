from __future__ import annotations

import itertools
from dataclasses import FrozenInstanceError, replace

import pytest

from codex_plugin_scanner.guard.action_lattice import GUARD_ACTION_LATTICE, GUARD_ACTION_SEVERITY
from codex_plugin_scanner.guard.runtime.effect_contract import (
    EFFECT_CONTRACT_SCHEMA_VERSION,
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
    derive_protection_state,
    maximum_action_floor,
)


def _effect(
    *,
    target_scope: EffectTargetScope = EffectTargetScope.WORKSPACE,
    reversibility: EffectReversibility = EffectReversibility.TRIVIALLY_RECOVERABLE,
    blast_radius: EffectBlastRadius = EffectBlastRadius.WORKSPACE,
    confidence: EffectConfidence = EffectConfidence.EXACT,
    uncertainty_reasons: tuple[UncertaintyKind, ...] = (),
    proof_requirements: frozenset[ProofRequirement] | None = None,
    schema_version: str = EFFECT_CONTRACT_SCHEMA_VERSION,
) -> EffectAssessment:
    return EffectAssessment(
        kind=EffectKind.PROCESS_EXECUTION,
        target_scope=target_scope,
        reversibility=reversibility,
        blast_radius=blast_radius,
        evidence_source=EffectEvidenceSource.LAUNCH_IDENTITY,
        confidence=confidence,
        containment=ContainmentRequirement.REQUIRED,
        proof_requirements=proof_requirements
        or frozenset({ProofRequirement.EXECUTABLE_IDENTITY, ProofRequirement.CONTAINMENT_IDENTITY}),
        uncertainty_reasons=uncertainty_reasons,
        schema_version=schema_version,
    )


def test_effect_taxonomy_is_complete_and_versioned() -> None:
    assert EFFECT_CONTRACT_SCHEMA_VERSION == "1.0.0"
    assert {effect.value for effect in EffectKind} == {
        "workspace-or-public-read",
        "sensitive-read",
        "workspace-write",
        "external-filesystem-write",
        "process-execution",
        "network-read",
        "network-write",
        "remote-state-read",
        "remote-state-mutation",
        "permission-or-access-change",
        "credential-or-secret-operation",
        "system-or-privilege-operation",
        "package-or-source-installation",
        "destructive-or-irreversible-operation",
        "guard-control-operation",
    }


def test_effect_assessment_is_immutable_and_binds_required_containment() -> None:
    assessment = _effect()

    with pytest.raises(FrozenInstanceError):
        assessment.kind = EffectKind.NETWORK_WRITE  # type: ignore[misc]
    with pytest.raises(ValueError, match="containment identity"):
        _effect(proof_requirements=frozenset({ProofRequirement.EXECUTABLE_IDENTITY}))
    with pytest.raises(ValueError, match="schema version"):
        _effect(schema_version="2.0.0")


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("kind", "process-execution", "EffectKind"),
        ("target_scope", object(), "EffectTargetScope"),
        ("reversibility", "reversible", "EffectReversibility"),
        ("blast_radius", "workspace", "EffectBlastRadius"),
        ("evidence_source", "parser", "EffectEvidenceSource"),
        ("confidence", "exact", "EffectConfidence"),
        ("containment", "required", "ContainmentRequirement"),
        ("proof_requirements", frozenset({"launch-chain"}), "proof_requirements members"),
        ("uncertainty_reasons", ("parser-failure",), "uncertainty_reasons members"),
    ],
)
def test_effect_assessment_rejects_untyped_enum_boundaries(field: str, value: object, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        replace(_effect(), **{field: value})


@pytest.mark.parametrize("confidence", [EffectConfidence.PARTIAL, EffectConfidence.DYNAMIC, EffectConfidence.UNKNOWN])
def test_non_exact_confidence_requires_typed_uncertainty(confidence: EffectConfidence) -> None:
    with pytest.raises(ValueError, match="require an uncertainty reason"):
        _effect(confidence=confidence)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("target_scope", EffectTargetScope.UNKNOWN),
        ("reversibility", EffectReversibility.UNKNOWN),
        ("blast_radius", EffectBlastRadius.UNKNOWN),
    ],
)
def test_unknown_effect_dimensions_require_non_exact_typed_uncertainty(field: str, value: object) -> None:
    arguments: dict[str, object] = {field: value}
    with pytest.raises(ValueError, match="unknown effect dimensions"):
        _effect(**arguments)  # type: ignore[arg-type]

    arguments.update(
        confidence=EffectConfidence.PARTIAL,
        uncertainty_reasons=(UncertaintyKind.UNKNOWN_EFFECT,),
    )
    assert _effect(**arguments).uncertainty_reasons == (UncertaintyKind.UNKNOWN_EFFECT,)  # type: ignore[arg-type]


def test_canonical_guard_action_floor_is_used_and_absence_reviews() -> None:
    assert maximum_action_floor(()) == "review"
    for left, right in itertools.product(GUARD_ACTION_LATTICE, repeat=2):
        result = maximum_action_floor((left, right))
        assert GUARD_ACTION_SEVERITY[result] >= GUARD_ACTION_SEVERITY[left]
        assert GUARD_ACTION_SEVERITY[result] >= GUARD_ACTION_SEVERITY[right]


def test_proof_route_is_separate_from_canonical_action_floor() -> None:
    bases = {DecisionBasis("allow", route) for route in ProofRoute}

    assert {basis.action_floor for basis in bases} == {"allow"}
    assert {basis.proof_route for basis in bases} == set(ProofRoute)
    with pytest.raises(ValueError, match="positive proof route"):
        DecisionBasis("allow", None)
    with pytest.raises(ValueError, match="canonical GuardAction"):
        DecisionBasis("invalid-action", ProofRoute.VERIFIED)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="ProofRoute"):
        DecisionBasis("allow", "verified")  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "health",
    [
        {"required_hooks": True},
        "healthy",
        type("DuckHealth", (), {"required_hooks": True})(),
    ],
)
def test_protection_state_rejects_non_contract_health_objects(health: object) -> None:
    with pytest.raises(ValueError, match="health must be a ProtectionHealth"):
        derive_protection_state(health)  # type: ignore[arg-type]
