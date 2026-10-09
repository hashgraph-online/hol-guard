"""Directory behavior fixtures use sources covered by the loaded native registry."""

from __future__ import annotations

import shutil
from pathlib import Path

from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY


def copy_projected_contribution_sources(source: Path, destination: Path) -> None:
    """Keep pending additions in contribution tests, outside projected-directory fixtures."""
    catalog_ids = {row.extension_id for row in BUILT_IN_COMMAND_EXTENSION_REGISTRY.extensions}
    for family, pattern in (
        ("extensions", "command.*.json"),
        ("mcp-servers", "mcp.*.json"),
        ("command-sources", "command.*.json"),
    ):
        directory = destination / "contributions" / family
        shutil.copytree(source / "contributions" / family, directory)
        for path in directory.glob(pattern):
            identity = path.stem
            if family == "mcp-servers":
                identity = "command.mcp-" + identity.removeprefix("mcp.")
            if identity not in catalog_ids:
                path.unlink()
