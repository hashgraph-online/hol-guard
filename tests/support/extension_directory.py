"""Directory behavior fixtures use sources covered by the loaded native registry."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from tests.support.extension_contributions import command_descriptor_fixture


def copy_projected_contribution_sources(source: Path, destination: Path) -> None:
    """Keep pending additions in contribution tests, outside projected-directory fixtures."""
    catalog_ids = {row.extension_id for row in BUILT_IN_COMMAND_EXTENSION_REGISTRY.extensions}
    for family, pattern in (
        ("extensions", "command.*.json"),
        ("mcp-servers", "mcp.*.json"),
        ("command-sources", "command.*.json"),
    ):
        directory = destination / "contributions" / family
        source_directory = source / "contributions" / family
        if family == "extensions" and not source_directory.exists():
            directory.mkdir(parents=True)
            # Directory contract fixtures need metadata for the loaded registry,
            # even when development has staged only the native catalog.
            for path in (source / "contributions/command-sources").glob("command.*.json"):
                if path.stem in catalog_ids:
                    payload = command_descriptor_fixture(path.stem)
                    (directory / path.name).write_text(json.dumps(payload))
        else:
            shutil.copytree(source_directory, directory)
        for path in directory.glob(pattern):
            identity = path.stem
            if family == "mcp-servers":
                identity = "command.mcp-" + identity.removeprefix("mcp.")
            if identity not in catalog_ids:
                path.unlink()
