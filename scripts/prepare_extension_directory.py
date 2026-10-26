"""Validate the full paged directory and stage bounded legacy compatibility.

The local unavailability marker is build evidence. Publication authenticates the
same marker contract with the distribution root and release provenance.
"""

from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path

import export_extension_directory as legacy
import render_command_extension_directory as markdown
from extension_delivery_legacy import UNAVAILABLE, preflight, unavailable_marker
from extension_pack_directory import public_entry
from native_directory_inventory import ROOT, catalog_rows, compiled_inventory, source_compiler
from native_projection_inventory import ProjectionInventory


def prepare(compiler: Path | None = None, *, check: bool = False, root: Path = ROOT, inventory=None):
    from codex_plugin_scanner.guard.runtime.generated_command_catalog_loader import _extension

    with compiled_inventory(compiler, root=root, inventory=inventory) as (directory, reader, release):
        extensions, public_ids = [], set()
        for identity, _, row in catalog_rows(reader, release):
            entry = public_entry(root, [row])
            if entry["runtimeExtensionId"] != identity or entry["id"] in public_ids:
                raise ValueError("public directory ownership differs from native packs")
            public_ids.add(entry["id"])
            extensions.append(_extension(row))
        if len(public_ids) != release["extensions"]:
            raise ValueError("public directory ownership is incomplete")
        sources = {
            path.stem
            for family in ("extensions", "mcp-servers")
            for path in (root / "contributions" / family).glob("*.json")
        }
        if sources != public_ids:
            raise ValueError("public contribution sources differ from native pack ownership")
        if any(path.stem not in public_ids for path in (root / "contributions/extension-listings").glob("*.json")):
            raise ValueError("a listing must belong to an existing native contribution")
        code = preflight(directory, release)
        # Reuse already validated pack metadata; never recompile a full aggregate.
        rendered = None
        if code is None:
            try:
                rendered = legacy.render_directories(root, extensions=extensions)
            except ValueError as error:
                if str(error) != "Public directory exceeds its byte budget":
                    raise
                code = "directory-bytes"
        marker = root / "docs/guard/extensions" / UNAVAILABLE
        if code is not None:
            source = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
            content = json.dumps(unavailable_marker(source, code), sort_keys=True, separators=(",", ":")) + "\n"
            if check:
                if marker.read_text() != content:
                    raise ValueError("legacy unavailability marker differs from current validated sources")
            else:
                legacy.write_catalog(marker, content)
        elif rendered is not None:
            if check and marker.exists():
                raise ValueError("legacy unavailability marker is stale")
            if not check and marker.exists():
                marker.unlink()
            for original, content in rendered.items():
                target = root / original.relative_to(ROOT)
                if check:
                    if target.read_text() != content:
                        raise ValueError("legacy public directory is stale")
                else:
                    legacy.write_catalog(target, content)
        path = root / "docs/guard/extensions/README.md"
        current = path.read_text()
        document = markdown.render_document(current, extensions=extensions)
        if check:
            if current != document:
                raise ValueError("extension Markdown directory is stale")
        else:
            path.write_text(document)
    return {"extensions": len(extensions), "legacy": code or "available"}


def prepare_and_check(compiler: Path | None = None, *, root: Path = ROOT):
    """Run both directory gates with one private, revalidated pack inventory."""
    compiler = compiler or source_compiler()
    with ProjectionInventory(root, compiler) as inventory:
        prepare(compiler, root=root, check=False, inventory=inventory)
        return prepare(compiler, root=root, check=True, inventory=inventory)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compiler", type=Path)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--write-and-check", action="store_true")
    args = parser.parse_args(argv)
    result = prepare_and_check(args.compiler) if args.write_and_check else prepare(args.compiler, check=args.check)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
