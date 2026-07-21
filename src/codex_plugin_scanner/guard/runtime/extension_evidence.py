"""Immutable, lossless evidence contract for command safety extensions."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import Final, cast

from codex_plugin_scanner.guard.action_lattice import guard_action_severity, is_guard_action
from codex_plugin_scanner.guard.models import GuardAction

from .effect_contract import (
    UNCERTAINTY_FLOOR,
    EffectKind,
    ProofRequirement,
    UncertaintyKind,
    maximum_action_floor,
)

_STABLE_ID: Final[re.Pattern[str]] = re.compile(r"[a-z][a-z0-9]*(?:[.-][a-z0-9]+)*")
_SEMANTIC_VERSION: Final[re.Pattern[str]] = re.compile(
    r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    + r"(?:-[0-9a-z]+(?:[.-][0-9a-z]+)*)?(?:\+[0-9a-z]+(?:[.-][0-9a-z]+)*)?"
)
_CANONICAL_REFERENCE: Final[re.Pattern[str]] = re.compile(r"[a-z][a-z0-9_-]*:[a-z0-9][a-z0-9._/-]*")
EXTENSION_EVIDENCE_SCHEMA_VERSION: Final = "1.0.0"


class ExtensionMatchClass(str, Enum):
    UNSAFE = "unsafe"
    UNCERTAINTY = "uncertainty"


class EvidenceSeverity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class SafeVariantOutcome(str, Enum):
    OWNED_RULE_NOT_RAISED = "owned-rule-not-raised"


@dataclass(frozen=True, slots=True)
class ExtensionRuleIdentity:
    extension_id: str
    extension_version: str
    rule_id: str
    rule_version: str

    def __post_init__(self) -> None:
        _require_stable_id(self.extension_id, "extension_id")
        _require_stable_id(self.rule_id, "rule_id")
        _require_stable_version(self.extension_version, "extension_version")
        _require_stable_version(self.rule_version, "rule_version")
        if not self.rule_id.startswith(f"{self.extension_id}."):
            raise ValueError("rule_id must be owned by extension_id")


@dataclass(frozen=True, slots=True)
class OwnedSafeVariant:
    """A safe outcome that can neutralize only its exact owning rule match."""

    identity: ExtensionRuleIdentity
    safe_variant_id: str
    outcome: SafeVariantOutcome

    def __post_init__(self) -> None:
        _require_identity(self.identity, "safe_variant.identity")
        _require_stable_id(self.safe_variant_id, "safe_variant.safe_variant_id")
        _require_enum(self.outcome, SafeVariantOutcome, "safe_variant.outcome")


SemanticEvidenceKey = tuple[
    str,
    str,
    str,
    str,
    str,
    str,
    str,
    str,
    str,
    str,
    tuple[str, ...],
    tuple[str, ...],
    tuple[str, ...],
    tuple[str, str, str, str, str, str, str],
    str,
]


@dataclass(frozen=True, slots=True)
class ExtensionEvidence:
    """One owned base rule match and its optional owned safe outcome."""

    identity: ExtensionRuleIdentity
    match_class: ExtensionMatchClass
    severity: EvidenceSeverity
    declared_floor: GuardAction
    base_fact: str
    segment_ref: str
    operation_ref: str
    effect_claims: frozenset[EffectKind]
    proof_requirements: frozenset[ProofRequirement]
    uncertainty_reasons: tuple[UncertaintyKind, ...] = ()
    safe_variant: OwnedSafeVariant | None = None
    schema_version: str = EXTENSION_EVIDENCE_SCHEMA_VERSION

    def __post_init__(self) -> None:
        _require_identity(self.identity, "identity")
        _require_enum(self.match_class, ExtensionMatchClass, "match_class")
        _require_enum(self.severity, EvidenceSeverity, "severity")
        if self.schema_version != EXTENSION_EVIDENCE_SCHEMA_VERSION:
            raise ValueError("unsupported extension evidence schema version")
        _require_stable_id(self.base_fact, "base_fact")
        _require_reference(self.segment_ref, "segment_ref")
        _require_reference(self.operation_ref, "operation_ref")
        _require_enum_frozenset(self.effect_claims, EffectKind, "effect_claims")
        _require_enum_frozenset(self.proof_requirements, ProofRequirement, "proof_requirements")
        _require_enum_tuple(self.uncertainty_reasons, UncertaintyKind, "uncertainty_reasons")
        declared_floor = _require_guard_action(self.declared_floor, "declared_floor")
        if self.safe_variant is not None:
            safe_variant = _require_safe_variant(self.safe_variant)
            if safe_variant.identity != self.identity:
                raise ValueError("safe variant must be owned by the exact matched rule identity")
        if self.match_class is ExtensionMatchClass.UNCERTAINTY:
            if self.safe_variant is not None:
                raise ValueError("uncertainty evidence cannot declare a safe variant")
            if not self.uncertainty_reasons:
                raise ValueError("uncertainty evidence requires at least one uncertainty reason")
            required_floor = maximum_action_floor(UNCERTAINTY_FLOOR[item] for item in self.uncertainty_reasons)
            if guard_action_severity(declared_floor) < guard_action_severity(required_floor):
                raise ValueError("uncertainty evidence cannot understate its canonical uncertainty floor")
        elif self.uncertainty_reasons:
            raise ValueError("unsafe evidence must use a separate uncertainty observation")
        elif guard_action_severity(declared_floor) < guard_action_severity("review"):
            raise ValueError("unsafe evidence must declare a review-or-stronger floor")

    @property
    def effective_floor(self) -> GuardAction | None:
        """Return no floor only when this exact owned match has a safe outcome."""

        if self.safe_variant is not None:
            return None
        return self.declared_floor

    @property
    def semantic_key(self) -> SemanticEvidenceKey:
        """Return a canonical, lossless key for equality, dedupe, and ordering."""

        safe_key = ("0", "", "", "", "", "", "")
        if self.safe_variant is not None:
            safe_key = (
                "1",
                self.safe_variant.identity.extension_id,
                self.safe_variant.identity.extension_version,
                self.safe_variant.identity.rule_id,
                self.safe_variant.identity.rule_version,
                self.safe_variant.safe_variant_id,
                self.safe_variant.outcome.value,
            )
        return (
            self.identity.extension_id,
            self.identity.extension_version,
            self.identity.rule_id,
            self.identity.rule_version,
            self.segment_ref,
            self.operation_ref,
            self.match_class.value,
            self.severity.value,
            self.declared_floor,
            self.base_fact,
            tuple(sorted(item.value for item in self.effect_claims)),
            tuple(sorted(item.value for item in self.proof_requirements)),
            tuple(sorted(item.value for item in self.uncertainty_reasons)),
            safe_key,
            self.schema_version,
        )


@dataclass(frozen=True, slots=True)
class ExtensionEvidenceBatch:
    """Canonical evidence order with permutation-independent floor composition."""

    evidence: tuple[ExtensionEvidence, ...]

    def __post_init__(self) -> None:
        observations = _require_tuple(self.evidence, "evidence")
        if any(not isinstance(item, ExtensionEvidence) for item in observations):
            raise ValueError("evidence members must be ExtensionEvidence values")
        ordered = tuple(sorted(self.evidence, key=lambda item: item.semantic_key))
        keys = tuple(item.semantic_key for item in ordered)
        if len(keys) != len(set(keys)):
            raise ValueError("duplicate extension evidence is not allowed")
        object.__setattr__(self, "evidence", ordered)

    def evidence_floor(self) -> GuardAction | None:
        """Compose effective floors without inventing a floor for neutralized evidence."""

        floors: list[GuardAction] = []
        for item in self.evidence:
            if (floor := item.effective_floor) is not None:
                floors.append(floor)
        if not floors:
            return None
        return maximum_action_floor(floors)


def _require_stable_id(value: object, label: str) -> None:
    if not isinstance(value, str) or len(value) > 128 or _STABLE_ID.fullmatch(value) is None:
        raise ValueError(f"{label} must be a stable lowercase identifier")


def _require_stable_version(value: object, label: str) -> None:
    if not isinstance(value, str) or _SEMANTIC_VERSION.fullmatch(value) is None:
        raise ValueError(f"{label} must be a stable semantic version")


def _require_reference(value: object, label: str) -> None:
    if not isinstance(value, str) or len(value) > 256 or _CANONICAL_REFERENCE.fullmatch(value) is None:
        raise ValueError(f"{label} must be a canonical reference")


def _require_non_empty_frozenset(value: object, label: str) -> frozenset[object]:
    if not isinstance(value, frozenset) or not value:
        raise ValueError(f"{label} must be a non-empty frozenset")
    return value


def _require_enum_tuple(value: object, enum_type: type[Enum], label: str) -> None:
    items = _require_tuple(value, label)
    if any(not isinstance(item, enum_type) for item in items):
        raise ValueError(f"{label} members must be {enum_type.__name__} values")
    if len(items) != len(set(items)):
        raise ValueError(f"{label} cannot contain duplicates")


def _require_tuple(value: object, label: str) -> tuple[object, ...]:
    if not isinstance(value, tuple):
        raise ValueError(f"{label} must be a tuple")
    return cast(tuple[object, ...], value)


def _require_guard_action(value: object, label: str) -> GuardAction:
    if not is_guard_action(value):
        raise ValueError(f"{label} must be a canonical GuardAction")
    return value


def _require_identity(value: object, label: str) -> None:
    if not isinstance(value, ExtensionRuleIdentity):
        raise ValueError(f"{label} must be an ExtensionRuleIdentity")


def _require_safe_variant(value: object) -> OwnedSafeVariant:
    if not isinstance(value, OwnedSafeVariant):
        raise ValueError("safe_variant must be an OwnedSafeVariant")
    return value


def _require_enum(value: object, enum_type: type[Enum], label: str) -> None:
    if not isinstance(value, enum_type):
        raise ValueError(f"{label} must be an exact {enum_type.__name__} value")


def _require_enum_frozenset(value: object, enum_type: type[Enum], label: str) -> None:
    items = _require_non_empty_frozenset(value, label)
    if any(not isinstance(item, enum_type) for item in items):
        raise ValueError(f"{label} members must be {enum_type.__name__} values")
