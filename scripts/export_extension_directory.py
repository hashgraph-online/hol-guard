#!/usr/bin/env python3
"""Export the public extension directory from trusted canonical source, without network I/O."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from codex_plugin_scanner.guard.extension_builder.errors import BuilderError
from codex_plugin_scanner.guard.extension_builder.io import checked_path
from codex_plugin_scanner.guard.extension_builder.listing import (
    DEFAULT_LIMITATIONS,
    MAX_TAGLINE_LENGTH,
    category_for_extension,
    load_listing,
)
from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.runtime.extension_contribution import validate_contribution_file
from codex_plugin_scanner.guard.runtime.extension_trust import trust_class_for
from codex_plugin_scanner.guard.runtime.mcp_server_contribution import (
    catalog_id_for_mcp_id,
    validate_mcp_contribution_file,
)

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "docs/guard/extensions/catalog.v1.json"
MAX_ENTRIES = 512
MAX_SOURCE_BYTES = 1_048_576


def _sources(root: Path) -> dict[str, tuple[str, dict[str, object], str]]:
    result: dict[str, tuple[str, dict[str, object], str]] = {}
    for directory, validate in (
        ("extensions", validate_contribution_file),
        ("mcp-servers", validate_mcp_contribution_file),
    ):
        parent = checked_path(root / "contributions" / directory)
        for path in sorted(parent.glob("*.json")):
            _ = checked_path(path)
            if not path.is_file() or path.stat().st_size > MAX_SOURCE_BYTES:
                raise ValueError("Contribution is not a bounded regular source file")
            payload = validate(path)
            extension_id = str(payload["id"])
            if path.name != f"{extension_id}.json" or extension_id in result:
                raise ValueError("Contribution identity is duplicated or does not match its filename")
            result[extension_id] = (
                path.relative_to(root).as_posix(),
                payload,
                "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest(),
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
    return json.dumps(export_directory(root), ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    _ = parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    try:
        rendered = render_directory()
    except (BuilderError, OSError, ValueError) as error:
        parser.error(str(error))
    if args.check:
        if not OUTPUT.is_file() or OUTPUT.read_text(encoding="utf-8") != rendered:
            parser.error("Extension catalog is stale; run python scripts/export_extension_directory.py")
    else:
        OUTPUT.parent.mkdir(parents=True, exist_ok=True)
        _ = OUTPUT.write_text(rendered, encoding="utf-8", newline="\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
