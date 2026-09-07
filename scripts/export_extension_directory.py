#!/usr/bin/env python3
"""Export the public extension directory from trusted canonical source, without network I/O."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import tempfile
from pathlib import Path

from codex_plugin_scanner.guard.extension_builder.errors import BuilderError
from codex_plugin_scanner.guard.extension_builder.io import checked_path, object_value, parse_json, read_bytes
from codex_plugin_scanner.guard.extension_builder.listing import (
    DEFAULT_LIMITATIONS,
    MAX_TAGLINE_LENGTH,
    category_for_extension,
    load_listing,
)
from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.runtime.extension_contribution import validate_contribution
from codex_plugin_scanner.guard.runtime.extension_trust import trust_class_for
from codex_plugin_scanner.guard.runtime.mcp_server_contribution import (
    catalog_id_for_mcp_id,
    validate_mcp_contribution,
)

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "docs/guard/extensions/catalog.v1.json"
MAX_ENTRIES = 512
MAX_SOURCE_BYTES = 1_048_576
MAX_CATALOG_BYTES = 1_048_576


def _sources(root: Path) -> dict[str, tuple[str, dict[str, object], str]]:
    result: dict[str, tuple[str, dict[str, object], str]] = {}
    for directory, validate in (
        ("extensions", validate_contribution),
        ("mcp-servers", validate_mcp_contribution),
    ):
        parent = checked_path(root / "contributions" / directory)
        for path in sorted(parent.glob("*.json")):
            content = read_bytes(path, limit=MAX_SOURCE_BYTES)
            payload = object_value(parse_json(content))
            validate(payload, filename=path.name)
            extension_id = str(payload["id"])
            if path.name != f"{extension_id}.json" or extension_id in result:
                raise ValueError("Contribution identity is duplicated or does not match its filename")
            result[extension_id] = (
                path.relative_to(root).as_posix(),
                payload,
                "sha256:" + hashlib.sha256(content).hexdigest(),
            )
            if len(result) > MAX_ENTRIES:
                raise ValueError("Public directory source count exceeds its budget")
    return result


def export_directory(root: Path = ROOT) -> dict[str, object]:
    sources = _sources(root)
    listings: dict[str, dict[str, object]] = {}
    parent = checked_path(root / "contributions/extension-listings")
    if parent.exists():
        paths = sorted(parent.glob("*.json"))
        if len(paths) > MAX_ENTRIES:
            raise ValueError("Listing count exceeds its budget")
        for path in paths:
            extension_id = path.stem
            if extension_id not in sources:
                raise ValueError("A listing must belong to an existing external native contribution")
            listings[extension_id] = load_listing(path, expected_id=extension_id)
    mcp_ids = {catalog_id_for_mcp_id(key): key for key in sources if key.startswith("mcp.")}
    entries: list[dict[str, object]] = []
    seen: set[str] = set()
    for native in BUILT_IN_COMMAND_EXTENSION_REGISTRY.extensions:
        extension_id = mcp_ids.get(native.extension_id, native.extension_id)
        source = sources.get(extension_id)
        payload: dict[str, object] = source[1] if source else {}
        listing = listings.get(extension_id, {})
        external = trust_class_for(native.extension_id) == "external"
        if external and source is None:
            raise ValueError("An external native extension must have a canonical contribution source")
        if native.required:
            model = "required"
        elif native.delegated_protection == "package-firewall":
            model = "package-firewall"
        elif external:
            model = "external-opt-in"
        else:
            model = "built-in"
        description = str(payload.get("description", native.description))
        entries.append(
            {
                "id": extension_id,
                "runtimeExtensionId": native.extension_id,
                "kind": "mcp" if extension_id.startswith("mcp.") else "command",
                "version": native.version,
                "name": str(payload.get("name", native.name)),
                "description": description,
                "tagline": listing.get("tagline", description[:MAX_TAGLINE_LENGTH].rstrip()),
                "category": listing.get("category", category_for_extension(extension_id)),
                "tags": listing.get("tags", []),
                "limitations": listing.get("limitations", list(DEFAULT_LIMITATIONS)),
                "documentationUrl": listing.get(
                    "documentationUrl",
                    "https://github.com/hashgraph-online/hol-guard/blob/main/docs/guard/extensions/README.md",
                ),
                "protectionModel": model,
                "trustClass": trust_class_for(native.extension_id),
                "claimPolicy": "provenance" if external else "project",
                "maintainerGithubIds": listing.get("maintainerGithubIds", []),
                "sourcePath": source[0]
                if source
                else "src/codex_plugin_scanner/guard/runtime/command_builtin_extension_registry.py",
                "contributionDigest": source[2] if source else None,
                "executables": list(native.executables),
                "actionClasses": list(native.action_classes),
                "ruleCount": len(native.rules),
                "permissionCount": len(native.permissions),
                "toolStates": payload.get("tools", []),
            }
        )
        seen.add(extension_id)
    if set(sources) - seen:
        raise ValueError("A source contribution is absent from the canonical native registry")
    if len(entries) > MAX_ENTRIES or len(seen) != len(entries):
        raise ValueError("Public directory has duplicate or excessive entries")
    return {
        "schemaVersion": "guard.extension-directory.v1",
        "entries": sorted(entries, key=lambda item: str(item["id"])),
    }


def render_directory(root: Path = ROOT) -> str:
    rendered = json.dumps(export_directory(root), ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n"
    if len(rendered.encode("utf-8")) > MAX_CATALOG_BYTES:
        raise ValueError("Public directory exceeds its byte budget")
    return rendered


def write_catalog(path: Path, rendered: str) -> None:
    """Stage complete bytes and replace a checked regular output, never truncate through a link."""
    target = checked_path(path)
    parent = checked_path(target.parent)
    if not parent.is_dir():
        raise ValueError("The catalog output parent must be an existing directory")
    if target.exists() and not stat.S_ISREG(target.lstat().st_mode):
        raise ValueError("The catalog output must be a regular file")
    content = rendered.encode("utf-8")
    if len(content) > MAX_CATALOG_BYTES:
        raise ValueError("Public directory exceeds its byte budget")
    descriptor, name = tempfile.mkstemp(prefix=".guard-catalog-", dir=parent)
    staged = Path(name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            _ = stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(staged, 0o644)
        _ = checked_path(parent)
        _ = checked_path(staged)
        _ = checked_path(target)
        if target.exists() and not stat.S_ISREG(target.lstat().st_mode):
            raise ValueError("The catalog output changed to a non-regular file")
        os.replace(staged, target)
    finally:
        if staged.exists():
            checked_path(staged).unlink()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    _ = parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    try:
        rendered = render_directory()
        if args.check:
            if read_bytes(OUTPUT, limit=MAX_CATALOG_BYTES) != rendered.encode("utf-8"):
                parser.error("Extension catalog is stale; run python scripts/export_extension_directory.py")
        else:
            write_catalog(OUTPUT, rendered)
    except (BuilderError, OSError, ValueError) as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
