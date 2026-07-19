"""Composite command evaluation shared by inspection and runtime policy."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from .command_decision_adapter import (
    command_uncertainties,
    decision_factors,
    effect_decision_to_dict,
    extension_evidence_batch,
    extension_uncertainties,
)
from .command_extension_observations import CommandExtensionObservation
from .command_extensions import (
    BUILT_IN_COMMAND_EXTENSION_REGISTRY,
    CommandSafetyExtension,
    CommandSafetyExtensionRegistry,
)
from .command_model import CanonicalCommand, parse_shell_command
from .command_rules import CommandRuleMatch, CommandRuleMode, CommandSafetyRule
from .effect_decision import EffectDecision, EffectDecisionRequest, evaluate_effect_decision

CommandDecisionFloor = Literal["allow", "monitor", "review", "block"]
_FLOOR_RANK: dict[CommandDecisionFloor, int] = {"allow": 0, "monitor": 1, "review": 2, "block": 3}
_SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}
_MODE_FLOOR: dict[CommandRuleMode, CommandDecisionFloor] = {
    "disabled": "allow",
    "monitor": "monitor",
    "review": "review",
    "enforce": "block",
    "required": "review",
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
    """All command matches plus the compatibility-preserving controlling action."""

    command: CanonicalCommand
    matches: tuple[OwnedCommandRuleMatch, ...]
    controlling_action_class: str | None
    controlling_reason: str | None
    controlling_rule_id: str | None
    minimum_action: CommandDecisionFloor
    extension_observations: tuple[CommandExtensionObservation[CommandSafetyExtension], ...]
    decision_plane: EffectDecision

    @property
    def risk_classes(self) -> tuple[str, ...]:
        return tuple(sorted({risk for owned in self.matches for risk in owned.match.rule.risk_classes}))

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


def evaluate_command(
    command_text: str,
    *,
    canonical_command: CanonicalCommand | None = None,
    compatibility_action_class: str | None = None,
    compatibility_reason: str | None = None,
    cwd: Path | None = None,
    home_dir: Path | None = None,
    registry: CommandSafetyExtensionRegistry = BUILT_IN_COMMAND_EXTENSION_REGISTRY,
) -> CompositeCommandEvaluation:
    """Evaluate every built-in rule without executing or persisting the command."""

    command = canonical_command or parse_shell_command(command_text, cwd=cwd, home_dir=home_dir)
    observations = registry.observations(command)
    structured = tuple(
        (item.extension, item.rule, item.effective_evidence) for item in observations if item.effective_evidence
    )
    selected = list(structured)
    selected_rule_ids = {rule.rule_id for _extension, rule, _evidence in selected}
    compatibility_rule: tuple[CommandSafetyExtension, CommandSafetyRule] | None = None
    if compatibility_action_class is not None:
        extension = registry.for_action_class(compatibility_action_class)
        rule = registry.rule_for_action_class(compatibility_action_class)
        if extension is not None and rule is not None and rule.rule_id not in selected_rule_ids:
            selected.append((extension, rule, ()))
            compatibility_rule = (extension, rule)

    owned_matches: list[OwnedCommandRuleMatch] = []
    for extension, rule, evidence in selected:
        action_class = rule.action_classes[0] if rule.action_classes else compatibility_action_class
        reason = rule.description
        if rule.compatibility_fallback and compatibility_reason is not None:
            reason = compatibility_reason
        owned_matches.append(
            OwnedCommandRuleMatch(
                extension=extension,
                match=CommandRuleMatch(
                    rule=rule,
                    action_class=action_class,
                    reason=reason,
                    command=command,
                    matcher_evidence=evidence,
                ),
            )
        )

    controlling_match = max(owned_matches, key=_match_precedence_key, default=None)
    controlling_action_class = compatibility_action_class
    controlling_reason = compatibility_reason
    if controlling_action_class is None and controlling_match is not None:
        controlling_action_class = controlling_match.match.action_class
        controlling_reason = controlling_match.match.reason
    minimum_action: CommandDecisionFloor = "allow"
    for owned in owned_matches:
        minimum_action = _stronger_floor(minimum_action, _rule_floor(owned))
    if compatibility_action_class is not None:
        minimum_action = _stronger_floor(minimum_action, "review")
    if command.confidence != "exact" and (compatibility_action_class is not None or owned_matches):
        minimum_action = _stronger_floor(minimum_action, "review")
    if extension_uncertainties(observations):
        minimum_action = "block"
    evidence_batch = extension_evidence_batch(command, observations)
    decision_plane = evaluate_effect_decision(
        EffectDecisionRequest(
            factors=decision_factors(
                evidence_batch,
                compatibility_action_class=compatibility_action_class,
                compatibility_rule=compatibility_rule,
            ),
            uncertainties=tuple(
                sorted(
                    {
                        *command_uncertainties(
                            command,
                            sensitive=compatibility_action_class is not None or bool(owned_matches),
                        ),
                        *extension_uncertainties(observations),
                    },
                    key=lambda item: item.value,
                )
            ),
        )
    )
    return CompositeCommandEvaluation(
        command=command,
        matches=tuple(owned_matches),
        controlling_action_class=controlling_action_class,
        controlling_reason=controlling_reason,
        controlling_rule_id=controlling_match.match.rule.rule_id if controlling_match is not None else None,
        minimum_action=minimum_action,
        extension_observations=observations,
        decision_plane=decision_plane,
    )


def _rule_floor(owned: OwnedCommandRuleMatch) -> CommandDecisionFloor:
    rule = owned.match.rule
    if owned.extension.required and rule.severity == "critical":
        return "block"
    if owned.extension.required:
        return "review"
    return _MODE_FLOOR[rule.default_mode]


def _stronger_floor(left: CommandDecisionFloor, right: CommandDecisionFloor) -> CommandDecisionFloor:
    return left if _FLOOR_RANK[left] >= _FLOOR_RANK[right] else right


def _match_precedence_key(owned: OwnedCommandRuleMatch) -> tuple[int, int, int]:
    return (
        _FLOOR_RANK[_rule_floor(owned)],
        _SEVERITY_RANK[owned.match.rule.severity],
        0 if owned.match.rule.compatibility_fallback else 1,
    )
