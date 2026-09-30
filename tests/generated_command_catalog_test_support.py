"""Factories for synthetic generated-catalog records used by boundary tests."""

from __future__ import annotations

from dataclasses import replace

from codex_plugin_scanner.guard.runtime.command_extensions import (
    BUILT_IN_COMMAND_EXTENSION_REGISTRY,
    CommandSafetyExtension,
)


def generated_extension(**changes: object) -> CommandSafetyExtension:
    base = BUILT_IN_COMMAND_EXTENSION_REGISTRY.get("command.api-gateway")
    assert base is not None
    values: dict[str, object] = {
        "rules": (),
        "required": False,
        "aliases": (),
        "dependencies": (),
        "conflicts": (),
        "permissions": (),
        "project_markers": (),
        "icon": {},
        "publisher": {},
        "surface": None,
        "mcp_launch": None,
        "mcp_tools": (),
    }
    values.update(changes)
    return replace(base, **values)
