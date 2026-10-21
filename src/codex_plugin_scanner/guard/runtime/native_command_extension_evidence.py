"""Project validated native command evidence onto generated catalog metadata."""

from __future__ import annotations

from dataclasses import dataclass
from typing import cast

from .command_extensions import CommandSafetyExtension, CommandSafetyRule
from .effect_contract import UncertaintyKind


class NativeCommandExtensionEvidenceError(RuntimeError):
    """Native extension evidence is absent, invalid, or bound to another catalog."""


@dataclass(frozen=True, slots=True)
class NativeMatcherEvidence:
    segment_index: int
    executable: str | None
    detail: str

    def to_dict(self) -> dict[str, object]:
        return {"segment_index": self.segment_index, "executable": self.executable, "detail": self.detail}


@dataclass(frozen=True, slots=True)
class NativeSafeVariantObservation:
    variant_id: str
    matcher_evidence: tuple[NativeMatcherEvidence, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "match_class": "safe-variant",
            "variant_id": self.variant_id,
            "matcher_evidence": [item.to_dict() for item in self.matcher_evidence],
        }


@dataclass(frozen=True, slots=True)
class NativeCommandExtensionObservation:
    extension: CommandSafetyExtension
    rule: CommandSafetyRule
    matcher_evidence: tuple[NativeMatcherEvidence, ...]
    safe_variants: tuple[NativeSafeVariantObservation, ...]
    uncertainty_reasons: tuple[UncertaintyKind, ...] = ()

    @property
    def effective_evidence(self) -> tuple[NativeMatcherEvidence, ...]:
        safe = {item.segment_index for variant in self.safe_variants for item in variant.matcher_evidence}
        return tuple(item for item in self.matcher_evidence if item.segment_index not in safe)

    def to_dict(self) -> dict[str, object]:
        classes = ["unsafe"] if self.matcher_evidence else []
        if self.uncertainty_reasons:
            classes.append("uncertainty")
        return {
            "extension_id": self.extension.extension_id,
            "extension_version": self.extension.version,
            "rule_id": self.rule.rule_id,
            "rule_version": self.rule.rule_version,
            "match_class": "uncertainty" if self.uncertainty_reasons else "unsafe",
            "match_classes": classes,
            "matcher_evidence": [item.to_dict() for item in self.matcher_evidence],
            "safe_variants": [item.to_dict() for item in self.safe_variants],
            "uncertainty_reasons": [item.value for item in self.uncertainty_reasons],
            "effective_segment_indexes": [item.segment_index for item in self.effective_evidence],
        }


def _evidence(value: object) -> tuple[NativeMatcherEvidence, ...]:
    if not isinstance(value, list):
        raise NativeCommandExtensionEvidenceError("native_command_extension_evidence_invalid")
    return tuple(
        NativeMatcherEvidence(
            cast(int, item["segment_index"]),
            cast(str | None, item["executable"]),
            cast(str, item["detail"]),
        )
        for item in cast(list[dict[str, object]], value)
    )
