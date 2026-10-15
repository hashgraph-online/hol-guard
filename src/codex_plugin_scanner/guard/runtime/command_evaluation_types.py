"""Stable command-evaluation records shared by policy and inspection."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from .command_decision_adapter import effect_decision_to_dict
from .command_extensions import CommandSafetyExtension, CommandSafetyRule
from .command_model import CanonicalCommand
from .effect_decision import EffectDecision
from .extension_control_contract import ControlResolution
from .extension_control_runtime import ExtensionControlDecisionEvidence
from .native_command_extension_evidence import NativeCommandExtensionObservation, NativeMatcherEvidence

CommandDecisionFloor = Literal["allow", "monitor", "review", "block"]


@dataclass(frozen=True, slots=True)
class CommandRuleMatch:
    rule: CommandSafetyRule
    action_class: str | None
    reason: str
    command: CanonicalCommand
    matcher_evidence: tuple[NativeMatcherEvidence, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return {
            "rule_id": self.rule.rule_id,
            "severity": self.rule.severity,
            "risk_classes": list(self.rule.risk_classes),
            "action_class": self.action_class,
            "reason": self.reason,
            "safer_alternatives": list(self.rule.safer_alternatives),
            "matcher_evidence": [item.to_dict() for item in self.matcher_evidence],
            "parse_confidence": self.command.confidence,
        }


@dataclass(frozen=True, slots=True)
class OwnedCommandRuleMatch:
    """One rule match with its owning extension."""

    extension: CommandSafetyExtension
    match: CommandRuleMatch

    def to_dict(self) -> dict[str, object]:
        return {
            "extension_id": self.extension.extension_id,
            **self.match.to_dict(),
        }


@dataclass(frozen=True, slots=True)
class CompositeCommandEvaluation:
    """Resident-computed command evaluation, projected onto Python records.

    Every field is decoded from the bound ``command_effect_decide`` result; no
    field is derived or relaxed on the Python side.
    """

    command: CanonicalCommand
    matches: tuple[OwnedCommandRuleMatch, ...]
    controlling_action_class: str | None
    controlling_reason: str | None
    controlling_rule_id: str | None
    minimum_action: CommandDecisionFloor
    extension_observations: tuple[NativeCommandExtensionObservation, ...]
    decision_plane: EffectDecision
    baseline_decision: EffectDecision
    risk_classes: tuple[str, ...]
    control_resolution: ControlResolution
    private_control_evidence: ExtensionControlDecisionEvidence | None

    @property
    def matched(self) -> bool:
        return self.controlling_action_class is not None or bool(self.matches)

    def to_dict(self) -> dict[str, object]:
        return {
            "security_identity": self.command.security_identity,
            "controlling_action_class": self.controlling_action_class,
            "controlling_reason": self.controlling_reason,
            "controlling_rule_id": self.controlling_rule_id,
            "minimum_action": self.minimum_action,
            "risk_classes": list(self.risk_classes),
            "matches": [owned.to_dict() for owned in self.matches],
            "extension_observations": [item.to_dict() for item in self.extension_observations],
            "decision_plane": effect_decision_to_dict(self.decision_plane),
            "parse_confidence": self.command.confidence,
            "uncertainty_reason": self.command.uncertainty_reason,
        }
