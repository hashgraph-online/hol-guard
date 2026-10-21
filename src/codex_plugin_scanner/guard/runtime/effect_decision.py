"""Typed transport for the Guard effect decisions the native runtime composes."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import Final, cast

from codex_plugin_scanner.guard.models import GuardAction

from .effect_contract import (
    ContainmentRequirement,
    DecisionBasis,
    EffectAssessment,
    ProofRequirement,
    ProofRoute,
)

EFFECT_DECISION_SCHEMA_VERSION: Final = "1.1.0"
_REASON_CODE: Final = re.compile(r"[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*")
_REFERENCE: Final = re.compile(r"[a-z][a-z0-9_-]*:[a-z0-9][a-z0-9._/-]*")
_SHA256: Final = re.compile(r"[0-9a-f]{64}")


class DecisionFactorSource(str, Enum):
    EFFECT = "effect"
    MATCH = "match"
    POLICY = "policy"
    CONTAINMENT = "containment"
    AUTHORIZATION = "authorization"
    ASSURANCE = "assurance"

    CONTROL = "control"


class FinalDisposition(str, Enum):
    SILENT_VERIFIED = "silent-verified"
    SILENT_CONTAINED = "silent-contained"
    WORKFLOW_AUTHORIZED = "workflow-authorized"
    WARN = "warn"
    REVIEW = "review"
    REQUIRE_REAPPROVAL = "require-reapproval"
    SANDBOX_REQUIRED = "sandbox-required"
    BLOCK = "block"


@dataclass(frozen=True, slots=True)
class PositiveProof:
    """Proof of exact binding for one decision factor."""

    route: ProofRoute
    binding_digest: str
    satisfied_requirements: frozenset[ProofRequirement]
    enforced: bool = False

    def __post_init__(self) -> None:
        route = cast(object, self.route)
        requirements = cast(object, self.satisfied_requirements)
        if not isinstance(route, ProofRoute):
            raise ValueError("route must be an exact ProofRoute value")
        if _SHA256.fullmatch(self.binding_digest) is None:
            raise ValueError("binding_digest must be a lowercase SHA-256 digest")
        if not isinstance(requirements, frozenset) or any(
            not isinstance(item, ProofRequirement) for item in requirements
        ):
            raise ValueError("satisfied_requirements must contain exact ProofRequirement values")
        if type(self.enforced) is not bool:
            raise ValueError("enforced must be a boolean")
        if self.route is ProofRoute.CONTAINED:
            if not self.enforced:
                raise ValueError("contained proof must be enforced")
            if ProofRequirement.CONTAINMENT_IDENTITY not in self.satisfied_requirements:
                raise ValueError("contained proof must bind containment identity")
        elif self.enforced:
            raise ValueError("only contained proof may claim enforcement")


@dataclass(frozen=True, slots=True)
class DecisionFactor:
    """One independently auditable lower bound on the final action."""

    source: DecisionFactorSource
    reason_code: str
    basis: DecisionBasis
    segment_ref: str | None = None
    operation_ref: str | None = None
    producer_ref: str | None = None
    evidence_digest: str | None = None
    assessment: EffectAssessment | None = None
    proof: PositiveProof | None = None

    def __post_init__(self) -> None:
        source = cast(object, self.source)
        basis = cast(object, self.basis)
        assessment = cast(object, self.assessment)
        proof = cast(object, self.proof)
        if not isinstance(source, DecisionFactorSource):
            raise ValueError("source must be an exact DecisionFactorSource value")
        if _REASON_CODE.fullmatch(self.reason_code) is None:
            raise ValueError("reason_code must be a stable lowercase identifier")
        if not isinstance(basis, DecisionBasis):
            raise ValueError("basis must be a DecisionBasis")
        if self.segment_ref is not None and _REFERENCE.fullmatch(self.segment_ref) is None:
            raise ValueError("segment_ref must be a canonical reference")
        if self.operation_ref is not None and _REFERENCE.fullmatch(self.operation_ref) is None:
            raise ValueError("operation_ref must be a canonical reference")
        if self.producer_ref is not None and _REFERENCE.fullmatch(self.producer_ref) is None:
            raise ValueError("producer_ref must be a canonical reference")
        if self.evidence_digest is not None and _SHA256.fullmatch(self.evidence_digest) is None:
            raise ValueError("evidence_digest must be a lowercase SHA-256 digest")
        if assessment is not None and not isinstance(assessment, EffectAssessment):
            raise ValueError("assessment must be an EffectAssessment")
        if self.source is DecisionFactorSource.EFFECT and self.assessment is None:
            raise ValueError("effect factors require an assessment")
        if self.source is not DecisionFactorSource.EFFECT and self.assessment is not None:
            raise ValueError("only effect factors may carry an assessment")
        if proof is not None and not isinstance(proof, PositiveProof):
            raise ValueError("proof must be a PositiveProof")
        if self.basis.proof_route is None:
            if self.proof is not None:
                raise ValueError("proof requires a matching proof route")
        elif self.proof is None or self.proof.route is not self.basis.proof_route:
            raise ValueError("permissive basis requires proof on the exact route")
        if self.proof is not None and self.assessment is not None:
            missing = self.assessment.proof_requirements - self.proof.satisfied_requirements
            if missing:
                raise ValueError("proof does not satisfy every effect requirement")
            if self.proof.route is ProofRoute.CONTAINED and self.assessment.containment not in {
                ContainmentRequirement.ELIGIBLE,
                ContainmentRequirement.REQUIRED,
            }:
                raise ValueError("contained proof is incompatible with the effect containment requirement")
            if (
                self.assessment.containment is ContainmentRequirement.REQUIRED
                and self.proof.route is not ProofRoute.CONTAINED
            ):
                raise ValueError("containment-required effects require contained proof")


@dataclass(frozen=True, slots=True)
class DecisionReason:
    source: DecisionFactorSource
    reason_code: str
    action_floor: GuardAction
    segment_ref: str | None
    operation_ref: str | None


@dataclass(frozen=True, slots=True)
class EffectDecision:
    action: GuardAction
    disposition: FinalDisposition
    controlling_reasons: tuple[DecisionReason, ...]
    reasons: tuple[DecisionReason, ...]
    proof_routes: frozenset[ProofRoute]
    schema_version: str = EFFECT_DECISION_SCHEMA_VERSION
