"""Shared proof helper for execution-owned containment paths."""

from __future__ import annotations

from datetime import datetime, timezone

from .runtime.containment_contract import ContainmentRequest
from .runtime.containment_executor import ContainmentExecutionResult
from .runtime.containment_health import ContainmentHealthEvidence, contained_positive_proof
from .runtime.effect_contract import ProofRequirement
from .runtime.effect_decision import PositiveProof

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


__all__ = ["containment_positive_proof"]
