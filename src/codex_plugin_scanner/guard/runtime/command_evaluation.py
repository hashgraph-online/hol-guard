"""Composite command evaluation shared by inspection and runtime policy."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY, CommandSafetyExtension
from .command_model import CanonicalCommand, parse_shell_command
from .command_rules import CommandRuleMatch


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
            "risk_classes": list(self.risk_classes),
            "matches": [owned.to_dict() for owned in self.matches],
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
) -> CompositeCommandEvaluation:
    """Evaluate every built-in rule without executing or persisting the command."""

    command = canonical_command or parse_shell_command(command_text, cwd=cwd, home_dir=home_dir)
    structured = BUILT_IN_COMMAND_EXTENSION_REGISTRY.matching_rules(command)
    selected = list(structured)
    selected_rule_ids = {rule.rule_id for _extension, rule, _evidence in selected}
    if compatibility_action_class is not None:
        extension = BUILT_IN_COMMAND_EXTENSION_REGISTRY.for_action_class(compatibility_action_class)
        rule = BUILT_IN_COMMAND_EXTENSION_REGISTRY.rule_for_action_class(compatibility_action_class)
        if extension is not None and rule is not None and rule.rule_id not in selected_rule_ids:
            selected.append((extension, rule, ()))

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

    controlling_action_class = compatibility_action_class
    controlling_reason = compatibility_reason
    if controlling_action_class is None and owned_matches:
        controlling_action_class = owned_matches[0].match.action_class
        controlling_reason = owned_matches[0].match.reason
    return CompositeCommandEvaluation(
        command=command,
        matches=tuple(owned_matches),
        controlling_action_class=controlling_action_class,
        controlling_reason=controlling_reason,
    )
