"""Pure, monotonic effect-capability decision plane for Guard commands."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import Final, TypeVar, cast

from codex_plugin_scanner.guard.action_lattice import guard_action_severity, is_guard_action
from codex_plugin_scanner.guard.models import GuardAction

from .effect_contract import (
    ContainmentRequirement,
    EffectAssessment,
    ProofRequirement,
    ProofRoute,
    UncertaintyKind,
    apply_uncertainty_floor,
    maximum_action_floor,
)
from .extension_evidence import ExtensionEvidenceBatch

EFFECT_DECISION_PLANE_SCHEMA_VERSION: Final = "1.0.0"
_STABLE_REFERENCE: Final[re.Pattern[str]] = re.compile(r"[a-z][a-z0-9_-]*:[a-z0-9][a-z0-9._:/-]*")
_FRAMED_DIGEST: Final[re.Pattern[str]] = re.compile(r"[a-z][a-z0-9-]*-v[1-9][0-9]*:[0-9a-f]{64}")
_T = TypeVar("_T")
_LAUNCH_PROOF_REQUIREMENTS: Final = frozenset(
    {
        ProofRequirement.EXECUTABLE_IDENTITY,
        ProofRequirement.LAUNCH_CHAIN,
        ProofRequirement.DEPENDENCY_PROVENANCE,
        ProofRequirement.CONFIGURATION_IDENTITY,
        ProofRequirement.WORKING_DIRECTORY_IDENTITY,
    }
)


class DecisionDisposition(str, Enum):
    SILENT_VERIFIED = "silent-verified"
    SILENT_CONTAINED = "silent-contained"
    WORKFLOW_AUTHORIZED = "workflow-authorized"
    REVIEW = "review"
    REQUIRE_REAPPROVAL = "require-reapproval"
    BLOCK = "block"


class DecisionSourceKind(str, Enum):
    EFFECT = "effect"
    EXTENSION = "extension"
    POLICY = "policy"
    LEGACY_HEURISTIC = "legacy-heuristic"
    UNCERTAINTY = "uncertainty"


class LaunchComponentKind(str, Enum):
    EXECUTABLE = "executable"
    WRAPPER = "wrapper"
    INTERPRETER = "interpreter"
    PATH_ENTRY = "path-entry"
    SYMLINK = "symlink"
    PACKAGE_ALIAS = "package-alias"
    PACKAGE_SOURCE = "package-source"
    MANIFEST = "manifest"
    LOCKFILE = "lockfile"
    CONFIGURATION = "configuration"
    REDIRECTION = "redirection"


@dataclass(frozen=True, slots=True)
class LaunchIdentityComponent:
    kind: LaunchComponentKind
    component_ref: str
    input_identity: str
    resolved_identity: str

    def __post_init__(self) -> None:
        _require_enum(self.kind, LaunchComponentKind, "kind")
        _require_reference(self.component_ref, "component_ref")
        _require_digest(self.input_identity, "input_identity")
        _require_digest(self.resolved_identity, "resolved_identity")

    @property
    def semantic_key(self) -> tuple[str, str, str, str]:
        return self.kind.value, self.component_ref, self.input_identity, self.resolved_identity


@dataclass(frozen=True, slots=True)
class LaunchIdentityBinding:
    command_security_identity: str
    working_directory_identity: str
    components: tuple[LaunchIdentityComponent, ...]

    def __post_init__(self) -> None:
        if not re.fullmatch(r"command-security-v[1-9][0-9]*:[0-9a-f]{64}", self.command_security_identity):
            raise ValueError("command_security_identity must be a framed command identity")
        _require_digest(self.working_directory_identity, "working_directory_identity")
        components_value = cast(object, self.components)
        if not isinstance(components_value, tuple) or not components_value:
            raise ValueError("components must be a non-empty tuple")
        components = cast(tuple[object, ...], components_value)
        if any(not isinstance(item, LaunchIdentityComponent) for item in components):
            raise ValueError("components must contain LaunchIdentityComponent values")
        typed_components = cast(tuple[LaunchIdentityComponent, ...], components)
        ordered = tuple(sorted(typed_components, key=lambda item: item.semantic_key))
        if len({item.semantic_key for item in ordered}) != len(ordered):
            raise ValueError("components cannot contain duplicate launch identities")
        if not any(item.kind is LaunchComponentKind.EXECUTABLE for item in ordered):
            raise ValueError("launch identity requires an executable component")
        object.__setattr__(self, "components", ordered)


@dataclass(frozen=True, slots=True)
class EffectProof:
    route: ProofRoute
    satisfied_requirements: frozenset[ProofRequirement]
    launch_identity: LaunchIdentityBinding | None = None
    containment_identity: str | None = None
    capability_identity: str | None = None

    def __post_init__(self) -> None:
        _require_enum(self.route, ProofRoute, "route")
        requirements_value = cast(object, self.satisfied_requirements)
        if not isinstance(requirements_value, frozenset):
            raise ValueError("satisfied_requirements must be a frozenset")
        requirements = requirements_value
        if any(not isinstance(item, ProofRequirement) for item in requirements):
            raise ValueError("satisfied_requirements must contain ProofRequirement values")
        if self.satisfied_requirements.intersection(_LAUNCH_PROOF_REQUIREMENTS) and self.launch_identity is None:
            raise ValueError("launch requirements require a LaunchIdentityBinding")
        if ProofRequirement.CONTAINMENT_IDENTITY in self.satisfied_requirements:
            _require_optional_digest(self.containment_identity, "containment_identity", required=True)
        elif self.containment_identity is not None:
            raise ValueError("containment identity cannot be supplied without its proof requirement")
        if ProofRequirement.CAPABILITY_CONSTRAINTS in self.satisfied_requirements:
            _require_optional_digest(self.capability_identity, "capability_identity", required=True)
        elif self.capability_identity is not None:
            raise ValueError("capability identity cannot be supplied without its proof requirement")
        if self.route is ProofRoute.CONTAINED and self.containment_identity is None:
            raise ValueError("contained proof requires containment identity")
        if self.route is ProofRoute.WORKFLOW_AUTHORIZED and self.capability_identity is None:
            raise ValueError("workflow proof requires capability identity")


@dataclass(frozen=True, slots=True)
class DecisionCandidate:
    source_id: str
    source_kind: DecisionSourceKind
    action_floor: GuardAction
    reason_code: str
    segment_ref: str | None = None

    def __post_init__(self) -> None:
        _require_reference(self.source_id, "source_id")
        _require_enum(self.source_kind, DecisionSourceKind, "source_kind")
        _require_action(self.action_floor, "action_floor")
        _require_reference(self.reason_code, "reason_code")
        if self.segment_ref is not None:
            _require_reference(self.segment_ref, "segment_ref")

    @property
    def semantic_key(self) -> tuple[str, str, str, str, str]:
        return (
            self.source_kind.value,
            self.source_id,
            self.segment_ref or "",
            self.action_floor,
            self.reason_code,
        )


@dataclass(frozen=True, slots=True)
class EffectObservation:
    segment_ref: str
    effect_ref: str
    assessment: EffectAssessment
    policy_floor: GuardAction
    proof: EffectProof | None = None
    workflow_authorization_eligible: bool = False
    expected_launch_identity: LaunchIdentityBinding | None = None

    def __post_init__(self) -> None:
        _require_reference(self.segment_ref, "segment_ref")
        _require_reference(self.effect_ref, "effect_ref")
        if not isinstance(cast(object, self.assessment), EffectAssessment):
            raise ValueError("assessment must be an EffectAssessment")
        _require_action(self.policy_floor, "policy_floor")
        if self.proof is not None and not isinstance(cast(object, self.proof), EffectProof):
            raise ValueError("proof must be an EffectProof")
        if type(self.workflow_authorization_eligible) is not bool:
            raise ValueError("workflow_authorization_eligible must be a boolean")
        launch_requirements = self.assessment.proof_requirements.intersection(_LAUNCH_PROOF_REQUIREMENTS)
        if launch_requirements and self.expected_launch_identity is None:
            raise ValueError("launch proof requirements require an expected launch identity")
        if self.expected_launch_identity is not None:
            if not isinstance(cast(object, self.expected_launch_identity), LaunchIdentityBinding):
                raise ValueError("expected_launch_identity must be a LaunchIdentityBinding")
            if not launch_requirements:
                raise ValueError("expected launch identity requires a launch proof requirement")


@dataclass(frozen=True, slots=True)
class EffectDecisionRequest:
    effects: tuple[EffectObservation, ...]
    extension_evidence: ExtensionEvidenceBatch
    candidates: tuple[DecisionCandidate, ...] = ()
    uncertainties: tuple[UncertaintyKind, ...] = ()
    schema_version: str = EFFECT_DECISION_PLANE_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != EFFECT_DECISION_PLANE_SCHEMA_VERSION:
            raise ValueError("unsupported effect decision plane schema version")
        _ = _require_tuple_members(self.effects, EffectObservation, "effects")
        if not isinstance(cast(object, self.extension_evidence), ExtensionEvidenceBatch):
            raise ValueError("extension_evidence must be an ExtensionEvidenceBatch")
        _ = _require_tuple_members(self.candidates, DecisionCandidate, "candidates")
        _ = _require_tuple_members(self.uncertainties, UncertaintyKind, "uncertainties")
        effect_keys = {(item.segment_ref, item.effect_ref) for item in self.effects}
        if len(effect_keys) != len(self.effects):
            raise ValueError("effects cannot contain duplicate segment/effect references")
        candidate_keys = {item.semantic_key for item in self.candidates}
        if len(candidate_keys) != len(self.candidates):
            raise ValueError("candidates cannot contain duplicates")


@dataclass(frozen=True, slots=True)
class EffectDecision:
    action: GuardAction
    disposition: DecisionDisposition
    controlling_sources: tuple[str, ...]
    reason_codes: tuple[str, ...]
    segment_actions: tuple[tuple[str, GuardAction], ...]
    proof_routes: tuple[ProofRoute, ...]
    schema_version: str = EFFECT_DECISION_PLANE_SCHEMA_VERSION

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "action": self.action,
            "disposition": self.disposition.value,
            "controlling_sources": list(self.controlling_sources),
            "reason_codes": list(self.reason_codes),
            "segment_actions": [
                {"segment_ref": segment_ref, "action": action} for segment_ref, action in self.segment_actions
            ],
            "proof_routes": [item.value for item in self.proof_routes],
        }


def evaluate_effect_decision(request: EffectDecisionRequest) -> EffectDecision:
    """Return one deterministic maximum action across all effects and evidence."""

    if not isinstance(cast(object, request), EffectDecisionRequest):
        raise ValueError("request must be an EffectDecisionRequest")
    candidates = list(request.candidates)
    proof_routes: set[ProofRoute] = set()
    segment_floors: dict[str, list[GuardAction]] = {}
    for candidate in request.candidates:
        if candidate.segment_ref is not None:
            segment_floors.setdefault(candidate.segment_ref, []).append(candidate.action_floor)
    for effect in request.effects:
        floor, route, reason = _effect_floor(effect)
        candidates.append(
            DecisionCandidate(effect.effect_ref, DecisionSourceKind.EFFECT, floor, reason, effect.segment_ref)
        )
        segment_floors.setdefault(effect.segment_ref, []).append(floor)
        if route is not None:
            proof_routes.add(route)
    for evidence in request.extension_evidence.evidence:
        extension_floor = evidence.effective_floor
        if extension_floor is None:
            continue
        candidates.append(
            DecisionCandidate(
                f"extension-evidence:{evidence.identity.rule_id}",
                DecisionSourceKind.EXTENSION,
                extension_floor,
                "reason:extension-floor",
                evidence.segment_ref,
            )
        )
        segment_floors.setdefault(evidence.segment_ref, []).append(extension_floor)
    if request.uncertainties:
        uncertainty_floor = apply_uncertainty_floor("allow", request.uncertainties)
        candidates.append(
            DecisionCandidate(
                "uncertainty:request",
                DecisionSourceKind.UNCERTAINTY,
                uncertainty_floor,
                "reason:typed-uncertainty",
            )
        )
    if not candidates:
        candidates.append(
            DecisionCandidate(
                "uncertainty:empty",
                DecisionSourceKind.UNCERTAINTY,
                "review",
                "reason:empty-decision-input",
            )
        )
    ordered = tuple(sorted(candidates, key=lambda item: item.semantic_key))
    action = maximum_action_floor(item.action_floor for item in ordered)
    controlling = tuple(item for item in ordered if item.action_floor == action)
    return EffectDecision(
        action=action,
        disposition=decision_disposition(action, proof_routes),
        controlling_sources=tuple(item.source_id for item in controlling),
        reason_codes=tuple(sorted({item.reason_code for item in ordered})),
        segment_actions=tuple(
            (segment_ref, maximum_action_floor(floors)) for segment_ref, floors in sorted(segment_floors.items())
        ),
        proof_routes=tuple(sorted(proof_routes, key=lambda item: item.value)),
    )


def _effect_floor(effect: EffectObservation) -> tuple[GuardAction, ProofRoute | None, str]:
    proof = effect.proof
    base_floor = effect.policy_floor
    if effect.assessment.uncertainty_reasons:
        base_floor = apply_uncertainty_floor(base_floor, effect.assessment.uncertainty_reasons)
    if proof is None or not effect.assessment.proof_requirements <= proof.satisfied_requirements:
        missing_floor: GuardAction = "review"
        if effect.assessment.containment is ContainmentRequirement.REQUIRED:
            missing_floor = "sandbox-required"
        return maximum_action_floor((base_floor, missing_floor)), None, "reason:effect-proof-incomplete"
    if effect.expected_launch_identity is not None and proof.launch_identity != effect.expected_launch_identity:
        mismatch_floor: GuardAction = "require-reapproval"
        if effect.assessment.containment is ContainmentRequirement.REQUIRED:
            mismatch_floor = "sandbox-required"
        return maximum_action_floor((base_floor, mismatch_floor)), None, "reason:launch-identity-mismatch"
    if effect.assessment.uncertainty_reasons:
        return base_floor, None, "reason:effect-uncertain"
    if proof.route is ProofRoute.WORKFLOW_AUTHORIZED:
        if not effect.workflow_authorization_eligible or base_floor == "block":
            return base_floor, None, "reason:workflow-authorization-ineligible"
        return "allow", proof.route, "reason:workflow-authorization-exact"
    if proof.route is ProofRoute.CONTAINED:
        if effect.assessment.containment not in {ContainmentRequirement.ELIGIBLE, ContainmentRequirement.REQUIRED}:
            return maximum_action_floor((base_floor, "review")), None, "reason:containment-ineligible"
        if base_floor == "block":
            return "block", None, "reason:block-floor-retained"
        return "allow", proof.route, "reason:containment-enforced"
    if guard_action_severity(base_floor) >= guard_action_severity("review"):
        return base_floor, None, "reason:policy-floor-retained"
    return base_floor, proof.route, "reason:positive-proof-complete"


def decision_disposition(action: GuardAction, proof_routes: set[ProofRoute]) -> DecisionDisposition:
    if action == "block":
        return DecisionDisposition.BLOCK
    if action in {"require-reapproval", "sandbox-required"}:
        return DecisionDisposition.REQUIRE_REAPPROVAL
    if action in {"review", "warn"}:
        return DecisionDisposition.REVIEW
    if action != "allow":
        raise ValueError(f"unexpected Guard action: {action}")
    if ProofRoute.WORKFLOW_AUTHORIZED in proof_routes:
        return DecisionDisposition.WORKFLOW_AUTHORIZED
    if ProofRoute.CONTAINED in proof_routes:
        return DecisionDisposition.SILENT_CONTAINED
    return DecisionDisposition.SILENT_VERIFIED


def _require_action(value: object, label: str) -> None:
    if not is_guard_action(value):
        raise ValueError(f"{label} must be a canonical GuardAction")


def _require_enum(value: object, expected: type[Enum], label: str) -> None:
    if not isinstance(value, expected):
        raise ValueError(f"{label} must be an exact {expected.__name__} value")


def _require_reference(value: object, label: str) -> None:
    if not isinstance(value, str) or len(value) > 256 or _STABLE_REFERENCE.fullmatch(value) is None:
        raise ValueError(f"{label} must be a canonical reference")


def _require_digest(value: object, label: str) -> None:
    if not isinstance(value, str) or _FRAMED_DIGEST.fullmatch(value) is None:
        raise ValueError(f"{label} must be a framed digest")


def _require_optional_digest(value: object, label: str, *, required: bool) -> None:
    if required and value is None:
        raise ValueError(f"{label} is required")
    if value is not None:
        _require_digest(value, label)


def _require_tuple_members(value: object, expected: type[_T], label: str) -> tuple[_T, ...]:
    if not isinstance(value, tuple):
        raise ValueError(f"{label} must be a tuple of {expected.__name__} values")
    items = cast(tuple[object, ...], value)
    if any(not isinstance(item, expected) for item in items):
        raise ValueError(f"{label} must be a tuple of {expected.__name__} values")
    return cast(tuple[_T, ...], items)
