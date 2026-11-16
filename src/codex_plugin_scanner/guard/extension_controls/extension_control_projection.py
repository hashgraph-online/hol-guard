"""Canonical effective-state projection for Extension Control Center clients.

The native runtime resolves every extension and permission for command
evaluation, through the resolver the command path uses, and reports what the
local and the managed layer set on each. The reason codes are the resolver's
factor and failure codes only, never private decision evidence.
"""

from __future__ import annotations

from pathlib import Path
from typing import Final

from ..native_extension_control import project_extension_controls
from ..runtime.command_extensions import CommandSafetyExtensionRegistry
from ..runtime.extension_control_runtime import ExtensionControlRuntimeSnapshot

EFFECTIVE_PROJECTION_SCHEMA: Final = "guard.daemon.extension-control-projection.v1"


def build_effective_extension_control_projection(
    registry: CommandSafetyExtensionRegistry,
    snapshot: ExtensionControlRuntimeSnapshot,
    *,
    guard_home: Path | None = None,
) -> dict[str, object]:
    """Project authoritative effective state using the production resolver."""

    extensions, permissions = project_extension_controls(
        registry, snapshot.layers, snapshot.authority_failure, guard_home=guard_home
    )
    return {
        "schema_version": EFFECTIVE_PROJECTION_SCHEMA,
        "revision": snapshot.revision,
        "catalog_digest": snapshot.catalog_digest,
        "health": snapshot.health.value,
        "extensions": extensions,
        "permissions": permissions,
    }
