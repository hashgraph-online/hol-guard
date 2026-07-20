"""Shared metadata contracts for built-in command extension catalogs."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, TypedDict

from .command_permission_catalog import (
    CommandPermissionSpec,
    delegated_permission,
    permissions_for_rules,
)
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
    permissions: tuple[CommandPermissionSpec, ...] = ()
    source: Literal["built-in", "local-admin", "signed-cloud"] = "built-in"
    required: bool = False
    delegated_protection: Literal["package-firewall"] | None = None
    ecosystem_ids: tuple[str, ...] = ()
    executables: tuple[str, ...] = ()
    project_markers: tuple[str, ...] = ()


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
    permissions: tuple[CommandPermissionSpec, ...]
    source: Literal["built-in", "local-admin", "signed-cloud"]
    required: bool
    delegated_protection: Literal["package-firewall"] | None
    ecosystem_ids: tuple[str, ...]
    executables: tuple[str, ...]
    project_markers: tuple[str, ...]


def command_extension_values(
    spec: CommandExtensionSpec,
    rules: tuple[CommandSafetyRule, ...],
) -> CommandExtensionValues:
    """Return typed registry constructor values for one extension spec."""

    extension_rules = tuple(rule for rule in rules if rule.rule_id.startswith(f"{spec.extension_id}."))
    if spec.permissions:
        permissions = spec.permissions
    elif spec.delegated_protection is not None:
        permissions = (
            delegated_permission(
                spec.extension_id,
                "1.0.0",
                spec.name,
                spec.description,
                spec.safer_alternatives,
            ),
        )
    else:
        permissions = permissions_for_rules(
            spec.extension_id,
            "1.0.0",
            extension_rules,
            configurable=not spec.required,
        )
    return {
        "extension_id": spec.extension_id,
        "version": "1.0.0",
        "name": spec.name,
        "description": spec.description,
        "action_classes": spec.action_classes,
        "risk_classes": spec.risk_classes,
        "safer_alternatives": spec.safer_alternatives,
        "rules": extension_rules,
        "permissions": permissions,
        "reference_urls": spec.reference_urls,
        "source": spec.source,
        "required": spec.required,
        "delegated_protection": spec.delegated_protection,
        "ecosystem_ids": spec.ecosystem_ids,
        "executables": spec.executables,
        "project_markers": spec.project_markers,
    }
