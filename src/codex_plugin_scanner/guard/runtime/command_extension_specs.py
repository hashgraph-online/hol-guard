"""Shared metadata contracts for built-in command extension catalogs."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TypedDict

from .command_rules import CommandSafetyRule


@dataclass(frozen=True, slots=True)
class CommandExtensionSpec:
    """Static metadata for a directly enforced command domain."""

    extension_id: str
    name: str
    description: str
    action_classes: tuple[str, ...]
    risk_classes: tuple[str, ...]
    safer_alternatives: tuple[str, ...]
    reference_urls: tuple[str, ...]


class CommandExtensionValues(TypedDict):
    """Constructor values for one built-in command extension."""

    extension_id: str
    version: str
    name: str
    description: str
    action_classes: tuple[str, ...]
    risk_classes: tuple[str, ...]
    safer_alternatives: tuple[str, ...]
    rules: tuple[CommandSafetyRule, ...]
    reference_urls: tuple[str, ...]


def command_extension_values(
    spec: CommandExtensionSpec,
    rules: tuple[CommandSafetyRule, ...],
) -> CommandExtensionValues:
    """Return typed registry constructor values for one extension spec."""

    extension_rules = tuple(rule for rule in rules if rule.rule_id.startswith(f"{spec.extension_id}."))
    return {
        "extension_id": spec.extension_id,
        "version": "1.0.0",
        "name": spec.name,
        "description": spec.description,
        "action_classes": spec.action_classes,
        "risk_classes": spec.risk_classes,
        "safer_alternatives": spec.safer_alternatives,
        "rules": extension_rules,
        "reference_urls": spec.reference_urls,
    }
