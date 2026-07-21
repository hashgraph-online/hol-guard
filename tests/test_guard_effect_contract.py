from __future__ import annotations

import itertools
from dataclasses import FrozenInstanceError, replace

import pytest

from codex_plugin_scanner.guard.action_lattice import GUARD_ACTION_LATTICE, GUARD_ACTION_SEVERITY
from codex_plugin_scanner.guard.runtime.effect_contract import (
    EFFECT_CONTRACT_SCHEMA_VERSION,
    TRUTHFUL_STATE_GLOSSARY,
    UNCERTAINTY_FLOOR,
    BoundaryVersionClassification,
    BoundaryVersionStatus,
    ContainmentRequirement,
    DecisionBasis,
    EffectAssessment,
    EffectBlastRadius,
    EffectConfidence,
    EffectEvidenceSource,
    EffectKind,
    EffectReversibility,
    EffectTargetScope,
    EnforcementOutcome,
    PostExecutionOutcome,
    PostExecutionProof,
    PostProofEligibility,
    ProofRequirement,
    ProofRoute,
    ProtectionHealth,
    TruthfulState,
    UncertaintyKind,
    apply_uncertainty_floor,
    decode_boundary_version,
    derive_activity_state,
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


def test_every_typed_uncertainty_retains_or_raises_every_canonical_floor() -> None:
    assert set(UNCERTAINTY_FLOOR) == set(UncertaintyKind)
    for current, uncertainty in itertools.product(GUARD_ACTION_LATTICE, UncertaintyKind):
        result = apply_uncertainty_floor(current, (uncertainty,))
        assert GUARD_ACTION_SEVERITY[result] >= GUARD_ACTION_SEVERITY[current]
        assert GUARD_ACTION_SEVERITY[result] >= GUARD_ACTION_SEVERITY[UNCERTAINTY_FLOOR[uncertainty]]
    with pytest.raises(ValueError, match="exact UncertaintyKind"):
        apply_uncertainty_floor("review", ("parser-failure",))  # type: ignore[arg-type]


def test_protection_state_is_derived_from_typed_health() -> None:
    healthy = ProtectionHealth(True, True, True, True, True)
    partial = ProtectionHealth(True, True, True, True, False)
    degraded = ProtectionHealth(False, True, True, True, True)

    assert derive_protection_state(healthy) is TruthfulState.PROTECTED
    assert derive_protection_state(partial) is TruthfulState.PARTIAL
    assert derive_protection_state(degraded) is TruthfulState.DEGRADED
    assert TRUTHFUL_STATE_GLOSSARY[TruthfulState.PARTIAL].label == "Partial"
    with pytest.raises(ValueError, match="ProtectionHealth fields must be booleans"):
        ProtectionHealth("false", True, True, True, True)  # type: ignore[arg-type]


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


def test_confirmed_states_require_strong_correlated_post_execution_proof() -> None:
    absent = PostExecutionProof(PostProofEligibility.INELIGIBLE, None)
    success = PostExecutionProof(PostProofEligibility.STRONG_CORRELATION, PostExecutionOutcome.SUCCESS)
    failure = PostExecutionProof(PostProofEligibility.STRONG_CORRELATION, PostExecutionOutcome.FAILURE)

    assert derive_activity_state(EnforcementOutcome.PERMITTED, absent) is TruthfulState.ALLOWED_UNCONFIRMED
    assert derive_activity_state(EnforcementOutcome.PERMITTED, success) is TruthfulState.CONFIRMED_SUCCESS
    assert derive_activity_state(EnforcementOutcome.PERMITTED, failure) is TruthfulState.CONFIRMED_FAILURE
    with pytest.raises(ValueError, match="ineligible"):
        PostExecutionProof(PostProofEligibility.INELIGIBLE, PostExecutionOutcome.SUCCESS)
    with pytest.raises(ValueError, match="only a permitted"):
        derive_activity_state(EnforcementOutcome.BLOCKED, success)
    with pytest.raises(ValueError, match="PostProofEligibility"):
        PostExecutionProof("ineligible", None)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="PostExecutionOutcome"):
        PostExecutionProof(PostProofEligibility.STRONG_CORRELATION, "success")  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="EnforcementOutcome"):
        derive_activity_state("permitted", absent)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "proof",
    [
        {"outcome": None},
        "success",
        type("DuckProof", (), {"outcome": None})(),
    ],
)
def test_activity_state_rejects_non_contract_proof_objects(proof: object) -> None:
    with pytest.raises(ValueError, match="proof must be a PostExecutionProof"):
        derive_activity_state(EnforcementOutcome.PERMITTED, proof)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("value", "status", "uncertainty"),
    [
        ("1.0.0", BoundaryVersionStatus.CURRENT, None),
        (None, BoundaryVersionStatus.MALFORMED, UncertaintyKind.MALFORMED_BOUNDARY_VERSION),
        ("1.0", BoundaryVersionStatus.MALFORMED, UncertaintyKind.MALFORMED_BOUNDARY_VERSION),
        ("01.0.0", BoundaryVersionStatus.MALFORMED, UncertaintyKind.MALFORMED_BOUNDARY_VERSION),
        ("\u0661.\u0660.\u0660", BoundaryVersionStatus.MALFORMED, UncertaintyKind.MALFORMED_BOUNDARY_VERSION),
        ("2.0.0", BoundaryVersionStatus.UNKNOWN, UncertaintyKind.UNKNOWN_BOUNDARY_VERSION),
        ("0.9.0", BoundaryVersionStatus.ROLLBACK, UncertaintyKind.ROLLBACK_BOUNDARY_VERSION),
    ],
)
def test_boundary_version_decoder_classifies_drift_fail_closed(
    value: object,
    status: BoundaryVersionStatus,
    uncertainty: UncertaintyKind | None,
) -> None:
    classification = decode_boundary_version(value)

    assert classification.status is status
    assert classification.uncertainty is uncertainty
    assert classification.action_floor is (None if uncertainty is None else "block")


def test_boundary_version_decoder_bounds_numeric_input_before_integer_conversion() -> None:
    classification = decode_boundary_version(f"1.{('9' * 5000)}.0")

    assert classification.status is BoundaryVersionStatus.MALFORMED
    assert classification.uncertainty is UncertaintyKind.MALFORMED_BOUNDARY_VERSION
    assert classification.action_floor == "block"


@pytest.mark.parametrize(
    "arguments",
    [
        (BoundaryVersionStatus.CURRENT, "2.0.0", "1.0.0", None, None),
        (
            BoundaryVersionStatus.CURRENT,
            "1.0.0",
            "1.0.0",
            UncertaintyKind.UNKNOWN_BOUNDARY_VERSION,
            "block",
        ),
        (
            BoundaryVersionStatus.MALFORMED,
            "invalid",
            "1.0.0",
            UncertaintyKind.MALFORMED_BOUNDARY_VERSION,
            "block",
        ),
        (
            BoundaryVersionStatus.UNKNOWN,
            "0.9.0",
            "1.0.0",
            UncertaintyKind.UNKNOWN_BOUNDARY_VERSION,
            "block",
        ),
        (
            BoundaryVersionStatus.ROLLBACK,
            "2.0.0",
            "1.0.0",
            UncertaintyKind.ROLLBACK_BOUNDARY_VERSION,
            "block",
        ),
        (BoundaryVersionStatus.UNKNOWN, "2.0.0", "1.0.0", "unknown-boundary-version", "allow"),
        ("current", "1.0.0", "1.0.0", None, None),
        (BoundaryVersionStatus.CURRENT, "1.0.0", "invalid", None, None),
    ],
)
def test_boundary_version_classification_rejects_direct_forgery(arguments: tuple[object, ...]) -> None:
    with pytest.raises(ValueError):
        BoundaryVersionClassification(*arguments)  # type: ignore[arg-type]
