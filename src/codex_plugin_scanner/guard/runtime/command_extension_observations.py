"""Lossless evidence observations for command safety extension matchers."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Generic, Protocol, TypeVar, cast

from .command_matcher_contracts import CommandMatcher, MatcherEvidence
from .command_model import CanonicalCommand
from .command_rules import CommandSafetyRule
from .effect_contract import UncertaintyKind


class CommandSafetyExtensionView(Protocol):
    @property
    def extension_id(self) -> str: ...

    @property
    def version(self) -> str: ...

    @property
    def rules(self) -> tuple[CommandSafetyRule, ...]: ...


_ExtensionT = TypeVar("_ExtensionT", bound=CommandSafetyExtensionView)


@dataclass(frozen=True, slots=True)
class SafeVariantObservation:
    """Every segment-level match emitted by one owned safe variant."""

    variant_id: str
    matcher_evidence: tuple[MatcherEvidence, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "match_class": "safe-variant",
            "variant_id": self.variant_id,
            "matcher_evidence": [item.to_dict() for item in self.matcher_evidence],
        }


@dataclass(frozen=True, slots=True)
class CommandExtensionObservation(Generic[_ExtensionT]):
    """Immutable base and safe-variant evidence from one extension rule."""

    extension: _ExtensionT
    rule: CommandSafetyRule
    matcher_evidence: tuple[MatcherEvidence, ...]
    safe_variants: tuple[SafeVariantObservation, ...]
    uncertainty_reasons: tuple[UncertaintyKind, ...] = ()

    @property
    def safe_segment_indexes(self) -> frozenset[int]:
        return frozenset(
            item.segment_index for observation in self.safe_variants for item in observation.matcher_evidence
        )

    @property
    def effective_evidence(self) -> tuple[MatcherEvidence, ...]:
        safe_indexes = self.safe_segment_indexes
        return tuple(item for item in self.matcher_evidence if item.segment_index not in safe_indexes)

    def to_dict(self) -> dict[str, object]:
        return {
            "extension_id": self.extension.extension_id,
            "extension_version": self.extension.version,
            "rule_id": self.rule.rule_id,
            "rule_version": self.rule.rule_version,
            "match_class": "unsafe",
            "matcher_evidence": [item.to_dict() for item in self.matcher_evidence],
            "safe_variants": [item.to_dict() for item in self.safe_variants],
            "uncertainty_reasons": [item.value for item in self.uncertainty_reasons],
            "effective_segment_indexes": [item.segment_index for item in self.effective_evidence],
        }


def observe_command_extensions(
    command: CanonicalCommand,
    extensions: tuple[_ExtensionT, ...],
    candidate_rule_ids: tuple[str, ...],
) -> tuple[CommandExtensionObservation[_ExtensionT], ...]:
    """Evaluate every candidate matcher without suppressing owned safe evidence."""

    candidates = frozenset(candidate_rule_ids)
    observations: list[CommandExtensionObservation[_ExtensionT]] = []
    for extension in extensions:
        for rule in extension.rules:
            if rule.matcher is None or rule.rule_id not in candidates:
                continue
            try:
                matcher_evidence = _validated_match(rule.matcher, command)
            except Exception:
                observations.append(
                    CommandExtensionObservation(
                        extension,
                        rule,
                        (),
                        (),
                        (UncertaintyKind.MATCHER_FAILURE,),
                    )
                )
                continue
            safe_variants: list[SafeVariantObservation] = []
            uncertainty_reasons: tuple[UncertaintyKind, ...] = ()
            for variant in rule.safe_variants:
                try:
                    evidence = _validated_match(variant.matcher, command)
                except Exception:
                    uncertainty_reasons = (UncertaintyKind.MATCHER_FAILURE,)
                    continue
                if evidence:
                    safe_variants.append(SafeVariantObservation(variant.variant_id, evidence))
            if matcher_evidence or safe_variants or uncertainty_reasons:
                observations.append(
                    CommandExtensionObservation(
                        extension,
                        rule,
                        matcher_evidence,
                        tuple(safe_variants),
                        uncertainty_reasons,
                    )
                )
    return tuple(observations)


def _validated_match(matcher: CommandMatcher, command: CanonicalCommand) -> tuple[MatcherEvidence, ...]:
    evidence_value = cast(object, matcher.match(command))
    if not isinstance(evidence_value, tuple):
        raise ValueError("matcher evidence must be a tuple of MatcherEvidence values")
    evidence = cast(tuple[object, ...], evidence_value)
    if any(not isinstance(item, MatcherEvidence) for item in evidence):
        raise ValueError("matcher evidence must be a tuple of MatcherEvidence values")
    return cast(tuple[MatcherEvidence, ...], evidence)
