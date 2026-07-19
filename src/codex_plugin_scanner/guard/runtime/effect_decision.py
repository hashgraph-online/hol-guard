"""Pure, monotonic composition for Guard effect decisions."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from enum import Enum
from typing import Final, cast

from codex_plugin_scanner.guard.action_lattice import guard_action_severity, is_guard_action
from codex_plugin_scanner.guard.models import GuardAction

from .effect_contract import (
    UNCERTAINTY_FLOOR,
    ContainmentRequirement,
    DecisionBasis,
    EffectAssessment,
    ProofRequirement,
    ProofRoute,
    UncertaintyKind,
    maximum_action_floor,
)
from .extension_evidence import ExtensionEvidenceBatch

EFFECT_DECISION_SCHEMA_VERSION: Final = "1.0.0"
_REASON_CODE: Final = re.compile(r"[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*")
_REFERENCE: Final = re.compile(r"[a-z][a-z0-9_-]*:[a-z0-9][a-z0-9._/-]*")
_SHA256: Final = re.compile(r"[0-9a-f]{64}")


class DecisionFactorSource(str, Enum):
    EFFECT = "effect"
    MATCH = "match"
    POLICY = "policy"
    CONTAINMENT = "containment"
    AUTHORIZATION = "authorization"


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

    @property
    def semantic_key(self) -> tuple[str, ...]:
        return (
            self.segment_ref or "",
            self.operation_ref or "",
            self.producer_ref or "",
            self.evidence_digest or "",
            self.source.value,
            self.reason_code,
            self.basis.action_floor,
            self.basis.proof_route.value if self.basis.proof_route is not None else "",
            *_assessment_key(self.assessment),
            *_proof_key(self.proof),
        )


@dataclass(frozen=True, slots=True)
class DecisionReason:
    source: DecisionFactorSource
    reason_code: str
    action_floor: GuardAction
    segment_ref: str | None
    operation_ref: str | None


@dataclass(frozen=True, slots=True)
class EffectDecisionRequest:
    factors: tuple[DecisionFactor, ...]
    uncertainties: tuple[UncertaintyKind, ...] = ()
    schema_version: str = EFFECT_DECISION_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != EFFECT_DECISION_SCHEMA_VERSION:
            raise ValueError("unsupported effect decision schema version")
        factors = _require_factor_tuple(cast(object, self.factors))
        uncertainties = _require_uncertainty_tuple(cast(object, self.uncertainties))
        ordered = tuple(sorted(factors, key=lambda item: item.semantic_key))
        keys = tuple(item.semantic_key for item in ordered)
        if len(keys) != len(set(keys)):
            raise ValueError("duplicate decision factors are not allowed")
        if len(uncertainties) != len(set(uncertainties)):
            raise ValueError("uncertainties cannot contain duplicates")
        object.__setattr__(self, "factors", ordered)
        object.__setattr__(self, "uncertainties", tuple(sorted(uncertainties, key=lambda item: item.value)))


@dataclass(frozen=True, slots=True)
class EffectDecision:
    action: GuardAction
    disposition: FinalDisposition
    controlling_reasons: tuple[DecisionReason, ...]
    reasons: tuple[DecisionReason, ...]
    proof_routes: frozenset[ProofRoute]
    schema_version: str = EFFECT_DECISION_SCHEMA_VERSION


def evaluate_effect_decision(request: EffectDecisionRequest) -> EffectDecision:
    """Return the maximum floor from every factor and uncertainty."""

    if not isinstance(cast(object, request), EffectDecisionRequest):
        raise ValueError("request must be an EffectDecisionRequest")
    reasons = [
        DecisionReason(
            item.source,
            item.reason_code,
            item.basis.action_floor,
            item.segment_ref,
            item.operation_ref,
        )
        for item in request.factors
    ]
    reasons.extend(
        DecisionReason(
            DecisionFactorSource.POLICY,
            f"uncertainty.{uncertainty.value}",
            UNCERTAINTY_FLOOR[uncertainty],
            None,
            None,
        )
        for uncertainty in request.uncertainties
    )
    for factor in request.factors:
        if factor.assessment is None:
            continue
        reasons.extend(
            DecisionReason(
                DecisionFactorSource.EFFECT,
                f"uncertainty.{uncertainty.value}",
                UNCERTAINTY_FLOOR[uncertainty],
                factor.segment_ref,
                factor.operation_ref,
            )
            for uncertainty in factor.assessment.uncertainty_reasons
        )
    reasons.sort(key=_reason_key)
    action = maximum_action_floor(reason.action_floor for reason in reasons)
    controlling = tuple(reason for reason in reasons if reason.action_floor == action)
    routes = frozenset(factor.proof.route for factor in request.factors if factor.proof is not None)
    return EffectDecision(
        action=action,
        disposition=_disposition(action, routes),
        controlling_reasons=controlling,
        reasons=tuple(reasons),
        proof_routes=routes,
    )


def factors_from_extension_evidence(batch: ExtensionEvidenceBatch) -> tuple[DecisionFactor, ...]:
    """Translate immutable extension observations without granting interaction."""

    if not isinstance(cast(object, batch), ExtensionEvidenceBatch):
        raise ValueError("batch must be an ExtensionEvidenceBatch")
    factors: list[DecisionFactor] = []
    for evidence in batch.evidence:
        floor = evidence.effective_floor
        if floor is None:
            continue
        factors.append(
            DecisionFactor(
                source=DecisionFactorSource.MATCH,
                reason_code=evidence.base_fact,
                basis=DecisionBasis(floor, None),
                segment_ref=evidence.segment_ref,
                operation_ref=evidence.operation_ref,
                producer_ref=(f"extension:{evidence.identity.extension_id}/{evidence.identity.rule_id}"),
                evidence_digest=_extension_evidence_digest(evidence.semantic_key),
            )
        )
    return tuple(sorted(factors, key=lambda item: item.semantic_key))


def _reason_key(reason: DecisionReason) -> tuple[str, str, str, str, int]:
    return (
        reason.segment_ref or "",
        reason.operation_ref or "",
        reason.source.value,
        reason.reason_code,
        guard_action_severity(reason.action_floor),
    )


def _disposition(action: GuardAction, routes: frozenset[ProofRoute]) -> FinalDisposition:
    if not is_guard_action(action):  # pragma: no cover - typed defensive boundary
        raise ValueError("action must be a canonical GuardAction")
    if action == "allow":
        if ProofRoute.WORKFLOW_AUTHORIZED in routes:
            return FinalDisposition.WORKFLOW_AUTHORIZED
        if ProofRoute.CONTAINED in routes:
            return FinalDisposition.SILENT_CONTAINED
        return FinalDisposition.SILENT_VERIFIED
    return FinalDisposition(action)


def _assessment_key(assessment: EffectAssessment | None) -> tuple[str, ...]:
    if assessment is None:
        return ("",) * 11
    return (
        assessment.kind.value,
        assessment.target_scope.value,
        assessment.reversibility.value,
        assessment.blast_radius.value,
        assessment.evidence_source.value,
        assessment.confidence.value,
        assessment.containment.value,
        ",".join(sorted(item.value for item in assessment.proof_requirements)),
        ",".join(sorted(item.value for item in assessment.uncertainty_reasons)),
        assessment.schema_version,
        "assessment",
    )


def _proof_key(proof: PositiveProof | None) -> tuple[str, ...]:
    if proof is None:
        return ("", "", "", "")
    return (
        proof.route.value,
        proof.binding_digest,
        ",".join(sorted(item.value for item in proof.satisfied_requirements)),
        "enforced" if proof.enforced else "not-enforced",
    )


def _extension_evidence_digest(semantic_key: object) -> str:
    payload = json.dumps(
        {"schema": "guard-extension-evidence-factor-v1", "semantic_key": semantic_key},
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    return hashlib.sha256(b"guard-extension-evidence-factor-v1\x00" + payload).hexdigest()


def _require_factor_tuple(value: object) -> tuple[DecisionFactor, ...]:
    if not isinstance(value, tuple):
        raise ValueError("factors must contain DecisionFactor values")
    items = cast(tuple[object, ...], value)
    if any(not isinstance(item, DecisionFactor) for item in items):
        raise ValueError("factors must contain DecisionFactor values")
    return cast(tuple[DecisionFactor, ...], items)


def _require_uncertainty_tuple(value: object) -> tuple[UncertaintyKind, ...]:
    if not isinstance(value, tuple):
        raise ValueError("uncertainties must contain exact UncertaintyKind values")
    items = cast(tuple[object, ...], value)
    if any(not isinstance(item, UncertaintyKind) for item in items):
        raise ValueError("uncertainties must contain exact UncertaintyKind values")
    return cast(tuple[UncertaintyKind, ...], items)
