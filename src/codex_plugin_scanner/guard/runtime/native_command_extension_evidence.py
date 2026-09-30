"""Project validated native command evidence onto generated catalog metadata."""

from __future__ import annotations

from dataclasses import dataclass
from typing import cast

from ..native_command_observations import validate_native_command_observations
from .command_extensions import CommandSafetyExtension, CommandSafetyExtensionRegistry, CommandSafetyRule
from .command_model import CanonicalCommand
from .effect_contract import UncertaintyKind
from .extension_control_runtime import ExtensionControlRuntimeSnapshot


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


def observations_from_native_evidence(
    value: object,
    registry: CommandSafetyExtensionRegistry,
    *,
    command: CanonicalCommand,
    control_snapshot: ExtensionControlRuntimeSnapshot,
) -> tuple[NativeCommandExtensionObservation, ...]:
    if not isinstance(value, dict):
        raise NativeCommandExtensionEvidenceError("native_command_extension_evidence_invalid")
    command_model = value.get("command_model")
    if not isinstance(command_model, dict) or command_model.get("normalized_text") != command.normalized_text:
        raise NativeCommandExtensionEvidenceError("native_command_extension_evidence_command_mismatch")
    validated = validate_native_command_observations(value.get("command_extensions"))
    if validated is None:
        raise NativeCommandExtensionEvidenceError("native_command_extension_evidence_invalid")
    binding = cast(dict[str, object], validated["binding"])
    if (
        binding["catalog_digest"] != registry.catalog_digest
        or binding["program_digest"] != registry.program_digest
        or binding["control_revision"] != control_snapshot.revision
        or binding["managed_control_revision"] != control_snapshot.managed_revision
        or binding["control_effective_digest"] != control_snapshot.effective_digest
    ):
        raise NativeCommandExtensionEvidenceError("native_command_extension_evidence_binding_mismatch")
    if validated["evaluation_error"] is not None:
        # The wire validator accepts only the known evaluation failure with
        # empty observations and a matching digest. Preserve that rejection as
        # a native hard block; it cannot supply a semantic match or allow proof.
        if (
            value.get("decision") != "deny"
            or value.get("policy_action") != "block"
            or value.get("minimum_action") != "block"
            or value.get("explicitly_benign") is not False
        ):
            raise NativeCommandExtensionEvidenceError("native_command_extension_evidence_invalid")
        return ()
    result: list[NativeCommandExtensionObservation] = []
    for raw in cast(list[dict[str, object]], validated["observations"]):
        extension = registry.get(cast(str, raw["extension_id"]))
        rule = registry.get_rule(cast(str, raw["rule_id"]))
        if (
            extension is None
            or rule is None
            or rule not in extension.rules
            or raw["extension_version"] != extension.version
            or raw["rule_version"] != rule.rule_version
        ):
            raise NativeCommandExtensionEvidenceError("native_command_extension_evidence_unknown_identity")
        variants = tuple(
            NativeSafeVariantObservation(
                cast(str, item["variant_id"]),
                _evidence(item["matcher_evidence"]),
            )
            for item in cast(list[dict[str, object]], raw["safe_variants"])
        )
        known_variants = {item.variant_id for item in rule.safe_variants}
        if any(item.variant_id not in known_variants for item in variants):
            raise NativeCommandExtensionEvidenceError("native_command_extension_evidence_unknown_identity")
        uncertainty = (UncertaintyKind.MATCHER_FAILURE,) if cast(list[str], raw["uncertainty_reasons"]) else ()
        result.append(
            NativeCommandExtensionObservation(
                extension,
                rule,
                _evidence(raw["matcher_evidence"]),
                variants,
                uncertainty,
            )
        )
    for raw in cast(list[dict[str, object]], validated["permission_observations"]):
        extension = registry.get(cast(str, raw["extension_id"]))
        permission = registry.permission(cast(str, raw["permission_id"]))
        if extension is None or permission is None or permission not in extension.permissions:
            raise NativeCommandExtensionEvidenceError("native_command_extension_evidence_unknown_identity")
    return tuple(result)
