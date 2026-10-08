"""Generated metadata for Guard's built-in command safety extensions.

Semantic command matching is owned by the packaged native program. This
module intentionally exposes metadata and relationship indexes only.
"""

from __future__ import annotations

from typing import Literal

from .command_action_risk_metadata import COMMAND_ACTION_RISK_CLASSES
from .generated_command_catalog import (
    GeneratedCommandCatalog,
    GeneratedCommandExtension,
    GeneratedCommandPermission,
    GeneratedCommandRule,
)
from .generated_command_catalog_loader import load_generated_command_catalog

COMMAND_EXTENSION_SCHEMA_VERSION = 2
CommandExtensionSource = Literal["built-in", "local-admin", "signed-cloud"]
CommandExtensionDelegate = Literal["package-firewall"]

# Compatibility names retained for control, inspection, and UI callers. The
# generated records contain no Python matcher or executable semantic object.
CommandSafetyExtension = GeneratedCommandExtension
CommandSafetyExtensionRegistry = GeneratedCommandCatalog
CommandPermissionSpec = GeneratedCommandPermission
CommandSafetyRule = GeneratedCommandRule


def risk_classes_for_command_action(action_class: str) -> tuple[str, ...]:
    """Return the stable runtime risk classes for an action-class label."""

    return COMMAND_ACTION_RISK_CLASSES.get(action_class.strip().lower(), ())


BUILT_IN_COMMAND_EXTENSION_REGISTRY = load_generated_command_catalog()

__all__ = [
    "BUILT_IN_COMMAND_EXTENSION_REGISTRY",
    "COMMAND_EXTENSION_SCHEMA_VERSION",
    "CommandExtensionDelegate",
    "CommandExtensionSource",
    "CommandPermissionSpec",
    "CommandSafetyExtension",
    "CommandSafetyExtensionRegistry",
    "CommandSafetyRule",
    "risk_classes_for_command_action",
]
