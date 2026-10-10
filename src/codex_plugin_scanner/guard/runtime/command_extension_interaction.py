"""Project central extension decisions onto the legacy request classifier."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class CommandExtensionInteractionMatch:
    action_class: str
    reason: str


@dataclass(frozen=True, slots=True)
class CommandExtensionInteraction:
    priority: CommandExtensionInteractionMatch | None
    fallback: CommandExtensionInteractionMatch | None
