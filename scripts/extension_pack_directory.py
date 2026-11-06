"""Project the existing public entry contract from one validated native pack."""

from __future__ import annotations

import hashlib
from pathlib import Path

import export_extension_directory as directory

from codex_plugin_scanner.guard.extension_builder.io import object_value, parse_json, read_bytes
from codex_plugin_scanner.guard.runtime.extension_contribution import validate_contribution
from codex_plugin_scanner.guard.runtime.generated_command_catalog_loader import _extension
from codex_plugin_scanner.guard.runtime.mcp_server_contribution import validate_mcp_contribution


def public_entry(root: Path, catalog: list) -> dict:
    if not isinstance(catalog, list) or len(catalog) != 1:
        raise ValueError("pack directory needs exactly one extension")
    native = _extension(catalog[0])
    mcp = native.surface == "mcp"
    identity = "mcp." + native.extension_id.removeprefix("command.mcp-") if mcp else native.extension_id
    kind = "mcp-servers" if mcp else "extensions"
    path = root / "contributions" / kind / f"{identity}.json"
    content = read_bytes(path, limit=directory.MAX_SOURCE_BYTES)
    payload = object_value(parse_json(content))
    validator = validate_mcp_contribution if mcp else validate_contribution
    validator(payload, filename=path.name)
    if payload.get("id") != identity:
        raise ValueError("public contribution identity differs from pack")
    sources = {identity: (path.relative_to(root).as_posix(), payload, "sha256:" + hashlib.sha256(content).hexdigest())}
    # A one-entry projection keeps legacy aggregate limits and semantics intact.
    listings = {}
    listing_path = root / "contributions/extension-listings" / f"{identity}.json"
    if listing_path.exists():
        content = read_bytes(listing_path, limit=directory.MAX_SOURCE_BYTES)
        listings[identity] = (
            listing_path.relative_to(root).as_posix(),
            directory.validate_listing(parse_json(content), expected_id=identity),
            "sha256:" + hashlib.sha256(content).hexdigest(),
        )
    command_sources = {}
    if not mcp:
        source_path = root / "contributions/command-sources" / f"{identity}.json"
        command_sources[source_path.relative_to(root).as_posix()] = read_bytes(source_path, limit=8 * 1024 * 1024)
    v1 = directory._export_directory(sources, listings, extensions=(native,))
    return directory._export_directory_v2(v1, sources, listings, command_sources)["entries"][0]
