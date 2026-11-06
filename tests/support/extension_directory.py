"""Bounded legacy behavior fixtures come from validated native pack metadata."""

from __future__ import annotations

import shutil
from pathlib import Path

from scripts.native_directory_inventory import native_extensions


def bounded_extensions():
    """Independent legacy exporter cases; full inventory is tested via packs."""
    identities = {"command.git", "command.blitcp", "command.mcp-filesystem"}
    extensions = tuple(row for row in native_extensions() if row.extension_id in identities)
    assert {row.extension_id for row in extensions} == identities
    return extensions


def copy_projected_contribution_sources(source: Path, destination: Path) -> None:
    """Copy the explicit legacy cases; complete canonical coverage lives in pack tests."""
    catalog_ids = {row.extension_id for row in bounded_extensions()}
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
