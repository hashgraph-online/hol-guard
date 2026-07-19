"""Project central extension decisions onto the legacy request classifier."""

from __future__ import annotations

from dataclasses import dataclass

from ..action_lattice import guard_action_severity
from .command_decision_adapter import evaluate_extension_interaction
from .command_extensions import CommandSafetyExtensionRegistry
from .command_model import CanonicalCommand


@dataclass(frozen=True, slots=True)
class CommandExtensionInteractionMatch:
    action_class: str
    reason: str


@dataclass(frozen=True, slots=True)
class CommandExtensionInteraction:
    priority: CommandExtensionInteractionMatch | None
    fallback: CommandExtensionInteractionMatch | None


def classify_command_extension_interaction(
    command: CanonicalCommand,
    registry: CommandSafetyExtensionRegistry,
) -> CommandExtensionInteraction:
    """Return sanitized legacy interaction projections from the central plane."""

    observations = registry.observations(command)
    has_signal = any(item.effective_evidence or item.uncertainty_reasons for item in observations)
    decision = evaluate_extension_interaction(command, observations)
    requires_interaction = has_signal and guard_action_severity(decision.action) >= guard_action_severity("review")
    if not requires_interaction:
        return CommandExtensionInteraction(None, None)
    if any(item.uncertainty_reasons for item in observations):
        return CommandExtensionInteraction(
            CommandExtensionInteractionMatch(
                "command extension matcher failure",
                "Guard blocked an extension matcher boundary failure without exposing matcher-provided data.",
            ),
            None,
        )

    matches = tuple(
        CommandExtensionInteractionMatch(item.rule.action_classes[0], item.rule.description)
        for item in observations
        if item.effective_evidence and item.rule.action_classes
    )
    priority = next(
        (item for item in matches if item.action_class == "GitHub Actions administrative command"),
        None,
    )
    return CommandExtensionInteraction(priority, matches[0] if matches else None)
