"""Shared proof and health helpers for execution-owned containment paths."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from .runtime.containment_contract import ContainmentRequest
from .runtime.containment_executor import ContainmentExecutionResult
from .runtime.containment_health import ContainmentHealthEvidence, contained_positive_proof
from .runtime.effect_contract import (
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
)
from .runtime.effect_decision import (
    DecisionFactor,
    DecisionFactorSource,
    EffectDecision,
    EffectDecisionRequest,
    PositiveProof,
    evaluate_effect_decision,
)

_EXECUTION_PROOF_REQUIREMENTS = (
    ProofRequirement.OPERATION_AND_TARGETS,
    ProofRequirement.WORKSPACE_IDENTITY,
    ProofRequirement.WORKING_DIRECTORY_IDENTITY,
    ProofRequirement.EXECUTABLE_IDENTITY,
    ProofRequirement.LAUNCH_CHAIN,
    ProofRequirement.PARSER_CONFIDENCE,
    ProofRequirement.EXPECTED_EFFECTS,
)


def containment_positive_proof(
    result: ContainmentExecutionResult,
    request: ContainmentRequest,
    health: ContainmentHealthEvidence,
    runtime_fingerprint: str,
) -> PositiveProof:
    """Bind one successful contained execution to current daemon health."""

    return contained_positive_proof(
        result.attestation,
        request,
        health,
        requirements=_EXECUTION_PROOF_REQUIREMENTS,
        now=datetime.now(timezone.utc),
        runtime_fingerprint=runtime_fingerprint,
    )


def load_current_containment_health(guard_home: Path) -> tuple[ContainmentHealthEvidence, str]:
    """Load current daemon containment health and reject incompatible evidence."""

    from .daemon.client import load_guard_surface_daemon_client
    from .daemon.manager import current_guard_daemon_runtime_fingerprint

    client = load_guard_surface_daemon_client(guard_home.resolve(strict=True))
    evidence = ContainmentHealthEvidence.from_mapping(client.containment_health())
    runtime_fingerprint = current_guard_daemon_runtime_fingerprint()
    errors = evidence.compatibility_errors(
        now=datetime.now(timezone.utc),
        runtime_fingerprint=runtime_fingerprint,
    )
    if errors:
        raise RuntimeError(f"containment health incompatible: {errors[0]}")
    return evidence, runtime_fingerprint


def contained_process_effect_decision(
    proof: PositiveProof,
    *,
    operation_id: str,
    producer_ref: str,
    reason_code: str | None = None,
) -> EffectDecision:
    """Evaluate a contained process-execution effect for one local runner."""

    requirements = frozenset(
        {
            ProofRequirement.OPERATION_AND_TARGETS,
            ProofRequirement.WORKSPACE_IDENTITY,
            ProofRequirement.WORKING_DIRECTORY_IDENTITY,
            ProofRequirement.EXECUTABLE_IDENTITY,
            ProofRequirement.LAUNCH_CHAIN,
            ProofRequirement.PARSER_CONFIDENCE,
            ProofRequirement.EXPECTED_EFFECTS,
            ProofRequirement.CONTAINMENT_IDENTITY,
        }
    )
    assessment = EffectAssessment(
        kind=EffectKind.PROCESS_EXECUTION,
        target_scope=EffectTargetScope.WORKSPACE,
        reversibility=EffectReversibility.TRIVIALLY_RECOVERABLE,
        blast_radius=EffectBlastRadius.WORKSPACE,
        evidence_source=EffectEvidenceSource.CONTAINMENT,
        confidence=EffectConfidence.STRONG,
        containment=ContainmentRequirement.REQUIRED,
        proof_requirements=requirements,
    )
    return evaluate_effect_decision(
        EffectDecisionRequest(
            factors=(
                DecisionFactor(
                    source=DecisionFactorSource.EFFECT,
                    reason_code=reason_code or f"routine-{operation_id}-contained",
                    basis=DecisionBasis("allow", ProofRoute.CONTAINED),
                    operation_ref=f"operation:{operation_id}",
                    producer_ref=producer_ref,
                    evidence_digest=proof.binding_digest,
                    assessment=assessment,
                    proof=proof,
                ),
            )
        )
    )


__all__ = ["contained_process_effect_decision", "containment_positive_proof", "load_current_containment_health"]
