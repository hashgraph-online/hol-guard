"""Pure contracts for Guard command effects, proof routes, and truthful states."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType
from typing import Final, TypeVar, cast

from codex_plugin_scanner.guard.action_lattice import (
    guard_action_severity,
    is_guard_action,
    most_restrictive_guard_action,
)
from codex_plugin_scanner.guard.models import GuardAction

EFFECT_CONTRACT_SCHEMA_VERSION: Final = "1.0.0"
_T = TypeVar("_T")


class EffectKind(str, Enum):
    WORKSPACE_OR_PUBLIC_READ = "workspace-or-public-read"
    SENSITIVE_READ = "sensitive-read"
    WORKSPACE_WRITE = "workspace-write"
    EXTERNAL_FILESYSTEM_WRITE = "external-filesystem-write"
    PROCESS_EXECUTION = "process-execution"
    NETWORK_READ = "network-read"
    NETWORK_WRITE = "network-write"
    REMOTE_STATE_READ = "remote-state-read"
    REMOTE_STATE_MUTATION = "remote-state-mutation"
    PERMISSION_OR_ACCESS_CHANGE = "permission-or-access-change"
    CREDENTIAL_OR_SECRET_OPERATION = "credential-or-secret-operation"
    SYSTEM_OR_PRIVILEGE_OPERATION = "system-or-privilege-operation"
    PACKAGE_OR_SOURCE_INSTALLATION = "package-or-source-installation"
    DESTRUCTIVE_OR_IRREVERSIBLE_OPERATION = "destructive-or-irreversible-operation"
    GUARD_CONTROL_OPERATION = "guard-control-operation"


class EffectTargetScope(str, Enum):
    PUBLIC_RESOURCE = "public-resource"
    WORKSPACE = "workspace"
    SENSITIVE_LOCAL = "sensitive-local"
    EXTERNAL_LOCAL = "external-local"
    NETWORK_ENDPOINT = "network-endpoint"
    REMOTE_RESOURCE = "remote-resource"
    SYSTEM = "system"
    GUARD = "guard"
    UNKNOWN = "unknown"


class EffectReversibility(str, Enum):
    REVERSIBLE = "reversible"
    TRIVIALLY_RECOVERABLE = "trivially-recoverable"
    RECOVERABLE_WITH_REVIEW = "recoverable-with-review"
    IRREVERSIBLE = "irreversible"
    UNKNOWN = "unknown"


class EffectBlastRadius(str, Enum):
    SINGLE_RESOURCE = "single-resource"
    WORKSPACE = "workspace"
    MULTIPLE_RESOURCES = "multiple-resources"
    SYSTEM_WIDE = "system-wide"
    CATASTROPHIC = "catastrophic"
    UNKNOWN = "unknown"


class EffectEvidenceSource(str, Enum):
    PARSER = "parser"
    EXTENSION = "extension"
    LAUNCH_IDENTITY = "launch-identity"
    MANIFEST = "manifest"
    LOCKFILE = "lockfile"
    CONFIGURATION = "configuration"
    POLICY = "policy"
    CONTAINMENT = "containment"
    CAPABILITY = "capability"
    RUNTIME = "runtime"


class EffectConfidence(str, Enum):
    EXACT = "exact"
    STRONG = "strong"
    PARTIAL = "partial"
    DYNAMIC = "dynamic"
    UNKNOWN = "unknown"


class ContainmentRequirement(str, Enum):
    NONE = "none"
    ELIGIBLE = "eligible"
    REQUIRED = "required"
    NOT_ELIGIBLE = "not-eligible"


class ProofRequirement(str, Enum):
    OPERATION_AND_TARGETS = "operation-and-targets"
    WORKSPACE_IDENTITY = "workspace-identity"
    REPOSITORY_IDENTITY = "repository-identity"
    REMOTE_RESOURCE_IDENTITY = "remote-resource-identity"
    WORKING_DIRECTORY_IDENTITY = "working-directory-identity"
    EXECUTABLE_IDENTITY = "executable-identity"
    LAUNCH_CHAIN = "launch-chain"
    DEPENDENCY_PROVENANCE = "dependency-provenance"
    CONFIGURATION_IDENTITY = "configuration-identity"
    SHELL_DATA_FLOW = "shell-data-flow"
    PARSER_CONFIDENCE = "parser-confidence"
    EXPECTED_EFFECTS = "expected-effects"
    CONTAINMENT_IDENTITY = "containment-identity"
    CAPABILITY_CONSTRAINTS = "capability-constraints"


class ProofRoute(str, Enum):
    VERIFIED = "verified"
    CONTAINED = "contained"
    WORKFLOW_AUTHORIZED = "workflow-authorized"


@dataclass(frozen=True, slots=True)
class DecisionBasis:
    action_floor: GuardAction
    proof_route: ProofRoute | None

    def __post_init__(self) -> None:
        action_floor = _require_guard_action(self.action_floor, "action_floor")
        if self.proof_route is not None:
            _require_enum(self.proof_route, ProofRoute, "proof_route")
        if guard_action_severity(action_floor) < guard_action_severity("review") and self.proof_route is None:
            raise ValueError("permissive action floors require a positive proof route")


class UncertaintyKind(str, Enum):
    PARTIAL_PARSE = "partial-parse"
    DYNAMIC_INPUT = "dynamic-input"
    UNSUPPORTED_INPUT = "unsupported-input"
    MALFORMED_INPUT = "malformed-input"
    PARSER_BUDGET_EXHAUSTED = "parser-budget-exhausted"
    MATCHER_FAILURE = "matcher-failure"
    PARSER_FAILURE = "parser-failure"
    UNRESOLVED_LAUNCH_IDENTITY = "unresolved-launch-identity"
    UNKNOWN_EFFECT = "unknown-effect"
    DEGRADED_CONTAINMENT = "degraded-containment"
    PROTECTION_HEALTH_DEGRADED = "protection-health-degraded"
    POLICY_VERSION_MISMATCH = "policy-version-mismatch"
    MALFORMED_BOUNDARY_VERSION = "malformed-boundary-version"
    UNKNOWN_BOUNDARY_VERSION = "unknown-boundary-version"
    ROLLBACK_BOUNDARY_VERSION = "rollback-boundary-version"


UNCERTAINTY_FLOOR: Final[Mapping[UncertaintyKind, GuardAction]] = MappingProxyType(
    {
        UncertaintyKind.PARTIAL_PARSE: "review",
        UncertaintyKind.DYNAMIC_INPUT: "review",
        UncertaintyKind.UNSUPPORTED_INPUT: "review",
        UncertaintyKind.MALFORMED_INPUT: "review",
        UncertaintyKind.PARSER_BUDGET_EXHAUSTED: "require-reapproval",
        UncertaintyKind.MATCHER_FAILURE: "block",
        UncertaintyKind.PARSER_FAILURE: "block",
        UncertaintyKind.UNRESOLVED_LAUNCH_IDENTITY: "require-reapproval",
        UncertaintyKind.UNKNOWN_EFFECT: "require-reapproval",
        UncertaintyKind.DEGRADED_CONTAINMENT: "block",
        UncertaintyKind.PROTECTION_HEALTH_DEGRADED: "block",
        UncertaintyKind.POLICY_VERSION_MISMATCH: "block",
        UncertaintyKind.MALFORMED_BOUNDARY_VERSION: "block",
        UncertaintyKind.UNKNOWN_BOUNDARY_VERSION: "block",
        UncertaintyKind.ROLLBACK_BOUNDARY_VERSION: "block",
    }
)


@dataclass(frozen=True, slots=True)
class EffectAssessment:
    kind: EffectKind
    target_scope: EffectTargetScope
    reversibility: EffectReversibility
    blast_radius: EffectBlastRadius
    evidence_source: EffectEvidenceSource
    confidence: EffectConfidence
    containment: ContainmentRequirement
    proof_requirements: frozenset[ProofRequirement]
    uncertainty_reasons: tuple[UncertaintyKind, ...] = ()
    schema_version: str = EFFECT_CONTRACT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        _require_enum(self.kind, EffectKind, "kind")
        _require_enum(self.target_scope, EffectTargetScope, "target_scope")
        _require_enum(self.reversibility, EffectReversibility, "reversibility")
        _require_enum(self.blast_radius, EffectBlastRadius, "blast_radius")
        _require_enum(self.evidence_source, EffectEvidenceSource, "evidence_source")
        _require_enum(self.confidence, EffectConfidence, "confidence")
        _require_enum(self.containment, ContainmentRequirement, "containment")
        if self.schema_version != EFFECT_CONTRACT_SCHEMA_VERSION:
            raise ValueError("unsupported effect contract schema version")
        _require_enum_frozenset(self.proof_requirements, ProofRequirement, "proof_requirements")
        _require_enum_tuple(self.uncertainty_reasons, UncertaintyKind, "uncertainty_reasons")
        uncertain_confidence = self.confidence in {
            EffectConfidence.PARTIAL,
            EffectConfidence.DYNAMIC,
            EffectConfidence.UNKNOWN,
        }
        if uncertain_confidence and not self.uncertainty_reasons:
            raise ValueError("partial, dynamic, and unknown effects require an uncertainty reason")
        if self.confidence is EffectConfidence.EXACT and self.uncertainty_reasons:
            raise ValueError("exact effects cannot carry uncertainty reasons")
        has_unknown_dimension = (
            self.target_scope is EffectTargetScope.UNKNOWN
            or self.reversibility is EffectReversibility.UNKNOWN
            or self.blast_radius is EffectBlastRadius.UNKNOWN
        )
        if has_unknown_dimension and (self.confidence is EffectConfidence.EXACT or not self.uncertainty_reasons):
            raise ValueError("unknown effect dimensions require non-exact confidence and typed uncertainty")
        if (
            self.containment is ContainmentRequirement.REQUIRED
            and ProofRequirement.CONTAINMENT_IDENTITY not in self.proof_requirements
        ):
            raise ValueError("required containment must bind containment identity")


def maximum_action_floor(floors: Iterable[GuardAction]) -> GuardAction:
    return most_restrictive_guard_action(*tuple(floors))


def apply_uncertainty_floor(current: GuardAction, uncertainties: Iterable[UncertaintyKind]) -> GuardAction:
    typed_uncertainties = _require_uncertainties(uncertainties)
    return maximum_action_floor((current, *(UNCERTAINTY_FLOOR[item] for item in typed_uncertainties)))


class TruthfulState(str, Enum):
    PROTECTED = "protected"
    PARTIAL = "partial"
    DEGRADED = "degraded"
    CHECKED = "checked"
    PERMITTED = "permitted"
    ALLOWED_UNCONFIRMED = "allowed-unconfirmed"
    CONFIRMED_SUCCESS = "confirmed-success"
    CONFIRMED_FAILURE = "confirmed-failure"
    INTERRUPTED = "interrupted"
    BLOCKED = "blocked"


@dataclass(frozen=True, slots=True)
class TruthfulStateTerm:
    label: str
    meaning: str


TRUTHFUL_STATE_GLOSSARY: Final[Mapping[TruthfulState, TruthfulStateTerm]] = MappingProxyType(
    {
        TruthfulState.PROTECTED: TruthfulStateTerm(
            "Protected",
            "Required hooks, services, policy, containment, tamper checks, and evidence health all pass.",
        ),
        TruthfulState.PARTIAL: TruthfulStateTerm(
            "Partial",
            "Core enforcement checks pass, but complete local evidence health cannot be proven.",
        ),
        TruthfulState.DEGRADED: TruthfulStateTerm(
            "Degraded",
            "One or more required protection checks do not pass.",
        ),
        TruthfulState.CHECKED: TruthfulStateTerm(
            "Checked",
            "Guard evaluated the command; this label does not classify it as a threat.",
        ),
        TruthfulState.PERMITTED: TruthfulStateTerm(
            "Permitted",
            "Guard permitted the command; this does not prove execution.",
        ),
        TruthfulState.ALLOWED_UNCONFIRMED: TruthfulStateTerm(
            "Allowed — unconfirmed",
            "Guard permitted the command but has no correlated post-execution proof.",
        ),
        TruthfulState.CONFIRMED_SUCCESS: TruthfulStateTerm(
            "Confirmed success",
            "Strongly correlated post-execution evidence reports successful completion.",
        ),
        TruthfulState.CONFIRMED_FAILURE: TruthfulStateTerm(
            "Confirmed failure",
            "Strongly correlated post-execution evidence reports failed completion.",
        ),
        TruthfulState.INTERRUPTED: TruthfulStateTerm(
            "Interrupted",
            "Guard required review or reapproval before execution could continue.",
        ),
        TruthfulState.BLOCKED: TruthfulStateTerm(
            "Blocked",
            "Guard prevented the command from proceeding.",
        ),
    }
)


@dataclass(frozen=True, slots=True)
class ProtectionHealth:
    required_hooks: bool
    daemon_and_policy: bool
    rules_and_containment: bool
    tamper_checks: bool
    evidence_health: bool

    def __post_init__(self) -> None:
        if any(type(cast(object, getattr(self, field))) is not bool for field in self.__slots__):
            raise ValueError("ProtectionHealth fields must be booleans")


class EnforcementOutcome(str, Enum):
    CHECKED = "checked"
    PERMITTED = "permitted"
    INTERRUPTED = "interrupted"
    BLOCKED = "blocked"


class PostProofEligibility(str, Enum):
    INELIGIBLE = "ineligible"
    STRONG_CORRELATION = "strong-correlation"


class PostExecutionOutcome(str, Enum):
    SUCCESS = "success"
    FAILURE = "failure"


@dataclass(frozen=True, slots=True)
class PostExecutionProof:
    eligibility: PostProofEligibility
    outcome: PostExecutionOutcome | None

    def __post_init__(self) -> None:
        _require_enum(self.eligibility, PostProofEligibility, "eligibility")
        if self.outcome is not None:
            _require_enum(self.outcome, PostExecutionOutcome, "outcome")
        if self.eligibility is PostProofEligibility.INELIGIBLE and self.outcome is not None:
            raise ValueError("ineligible post-execution proof cannot claim an outcome")
        if self.eligibility is PostProofEligibility.STRONG_CORRELATION and self.outcome is None:
            raise ValueError("strongly correlated post-execution proof requires an outcome")


def derive_protection_state(health: ProtectionHealth) -> TruthfulState:
    health = _require_instance(health, ProtectionHealth, "health")
    core_healthy = (
        health.required_hooks and health.daemon_and_policy and health.rules_and_containment and health.tamper_checks
    )
    if not core_healthy:
        return TruthfulState.DEGRADED
    if not health.evidence_health:
        return TruthfulState.PARTIAL
    return TruthfulState.PROTECTED


def derive_activity_state(outcome: EnforcementOutcome, proof: PostExecutionProof) -> TruthfulState:
    _require_enum(outcome, EnforcementOutcome, "outcome")
    proof = _require_instance(proof, PostExecutionProof, "proof")
    if outcome is not EnforcementOutcome.PERMITTED:
        if proof.outcome is not None:
            raise ValueError("only a permitted command may consume post-execution proof")
        return {
            EnforcementOutcome.CHECKED: TruthfulState.CHECKED,
            EnforcementOutcome.INTERRUPTED: TruthfulState.INTERRUPTED,
            EnforcementOutcome.BLOCKED: TruthfulState.BLOCKED,
        }[outcome]
    if proof.outcome is PostExecutionOutcome.SUCCESS:
        return TruthfulState.CONFIRMED_SUCCESS
    if proof.outcome is PostExecutionOutcome.FAILURE:
        return TruthfulState.CONFIRMED_FAILURE
    return TruthfulState.ALLOWED_UNCONFIRMED


class BoundaryVersionStatus(str, Enum):
    CURRENT = "current"
    MALFORMED = "malformed"
    UNKNOWN = "unknown"
    ROLLBACK = "rollback"


@dataclass(frozen=True, slots=True)
class BoundaryVersionClassification:
    status: BoundaryVersionStatus
    version: str | None
    expected_version: str
    uncertainty: UncertaintyKind | None
    action_floor: GuardAction | None

    def __post_init__(self) -> None:
        expected = _parse_boundary_version(self.expected_version)
        received = _parse_boundary_version(self.version)
        _require_enum(self.status, BoundaryVersionStatus, "status")
        if expected is None:
            raise ValueError("invalid boundary version classification")
        failure = {
            BoundaryVersionStatus.MALFORMED: UncertaintyKind.MALFORMED_BOUNDARY_VERSION,
            BoundaryVersionStatus.UNKNOWN: UncertaintyKind.UNKNOWN_BOUNDARY_VERSION,
            BoundaryVersionStatus.ROLLBACK: UncertaintyKind.ROLLBACK_BOUNDARY_VERSION,
        }.get(self.status)
        if self.status is BoundaryVersionStatus.CURRENT:
            valid = (received, self.uncertainty, self.action_floor) == (expected, None, None)
        elif failure is None or self.uncertainty is not failure or self.action_floor != "block":
            valid = False
        elif self.status is BoundaryVersionStatus.MALFORMED:
            valid = self.version is None
        else:
            valid = received is not None and (
                (self.status is BoundaryVersionStatus.UNKNOWN and received > expected)
                or (self.status is BoundaryVersionStatus.ROLLBACK and received < expected)
            )
        if not valid:
            raise ValueError("invalid boundary version classification")


def decode_boundary_version(
    value: object,
    *,
    current_version: str = EFFECT_CONTRACT_SCHEMA_VERSION,
) -> BoundaryVersionClassification:
    current = _parse_boundary_version(current_version)
    if current is None:
        raise ValueError("current_version must be a canonical semantic boundary version")
    received = _parse_boundary_version(value)
    if received is None:
        return _boundary_version_failure(BoundaryVersionStatus.MALFORMED, None, current_version)
    received_version = value if isinstance(value, str) else None
    if received == current:
        return BoundaryVersionClassification(
            BoundaryVersionStatus.CURRENT, received_version, current_version, None, None
        )
    if received < current:
        return _boundary_version_failure(BoundaryVersionStatus.ROLLBACK, received_version, current_version)
    return _boundary_version_failure(BoundaryVersionStatus.UNKNOWN, received_version, current_version)


def _boundary_version_failure(
    status: BoundaryVersionStatus, version: str | None, expected_version: str
) -> BoundaryVersionClassification:
    uncertainty = UncertaintyKind(f"{status.value}-boundary-version")
    return BoundaryVersionClassification(status, version, expected_version, uncertainty, UNCERTAINTY_FLOOR[uncertainty])


def _parse_boundary_version(value: object) -> tuple[int, int, int] | None:
    if not isinstance(value, str) or len(value) > 32:
        return None
    parts = value.split(".")
    if len(parts) != 3 or any(
        not part.isascii() or not part.isdigit() or len(part) > 9 or (len(part) > 1 and part.startswith("0"))
        for part in parts
    ):
        return None
    return int(parts[0]), int(parts[1]), int(parts[2])


def _require_guard_action(value: object, label: str) -> GuardAction:
    if not is_guard_action(value):
        raise ValueError(f"{label} must be a canonical GuardAction")
    return value


def _require_enum(value: object, enum_type: type[Enum], label: str) -> None:
    if not isinstance(value, enum_type):
        raise ValueError(f"{label} must be an exact {enum_type.__name__} value")


def _require_instance(value: object, expected_type: type[_T], label: str) -> _T:
    if not isinstance(value, expected_type):
        raise ValueError(f"{label} must be a {expected_type.__name__}")
    return value


def _require_uncertainties(values: Iterable[object]) -> tuple[UncertaintyKind, ...]:
    items = tuple(values)
    if any(not isinstance(item, UncertaintyKind) for item in items):
        raise ValueError("uncertainties must contain exact UncertaintyKind values")
    return cast(tuple[UncertaintyKind, ...], items)


def _require_enum_frozenset(value: object, enum_type: type[Enum], label: str) -> None:
    items = _require_non_empty_frozenset(value, label)
    if any(not isinstance(item, enum_type) for item in items):
        raise ValueError(f"{label} members must be {enum_type.__name__} values")


def _require_enum_tuple(value: object, enum_type: type[Enum], label: str) -> None:
    items = _require_tuple(value, label)
    if any(not isinstance(item, enum_type) for item in items):
        raise ValueError(f"{label} members must be {enum_type.__name__} values")
    if len(items) != len(set(items)):
        raise ValueError(f"{label} cannot contain duplicates")


def _require_non_empty_frozenset(value: object, label: str) -> frozenset[object]:
    if not isinstance(value, frozenset) or not value:
        raise ValueError(f"{label} must be a non-empty frozenset")
    return value


def _require_tuple(value: object, label: str) -> tuple[object, ...]:
    if not isinstance(value, tuple):
        raise ValueError(f"{label} must be a tuple")
    return cast(tuple[object, ...], value)
