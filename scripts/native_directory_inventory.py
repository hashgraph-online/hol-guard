"""Read complete directory metadata through the native bounded pack compiler.

Development orchestration only: Rust validates sources, relationships and packs.
No whole-catalog native program is constructed here.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
from contextlib import contextmanager
from functools import lru_cache
from pathlib import Path

# This module is also imported as scripts.native_directory_inventory by tests.
_SCRIPTS = str(Path(__file__).resolve().parent)
sys.path.insert(0, _SCRIPTS)

try:
    import build_native_command_packs as packs
    from command_pack_store import PackReader
    from extension_delivery_objects import entries
finally:
    sys.path.remove(_SCRIPTS)

ROOT = Path(__file__).resolve().parents[1]


def source_compiler() -> Path:
    configured = os.environ.get("HOL_GUARD_BUILD_SOURCE_COMPILER") or os.environ.get(
        "HOL_GUARD_NATIVE_TEST_SOURCE_COMPILER"
    )
    return Path(configured).resolve(strict=True) if configured else packs.bootstrap_compiler()


@contextmanager
def compiled_inventory(compiler: Path | None = None, *, root: Path = ROOT, inventory=None):
    if inventory is not None:
        with inventory.open(compiler or source_compiler(), root=root) as compiled:
            yield compiled
        return
    with tempfile.TemporaryDirectory(prefix="hol-guard-directory-") as scratch:
        directory = Path(scratch).resolve(strict=True)
        sys.path.insert(0, _SCRIPTS)
        try:
            packs.stage(compiler or source_compiler(), directory, source_root=root)
        finally:
            sys.path.remove(_SCRIPTS)
        release = json.loads((directory / "release.json").read_bytes())
        yield directory, PackReader(directory / "objects"), release


def catalog_rows(reader, release):
    for identity, reference in entries(reader, release["index"], release["extensions"]):
        manifest = reader.json(reference)
        catalog = reader.json(manifest["catalog"])
        if len(catalog) != 1 or catalog[0]["extension_id"] != identity:
            raise ValueError("directory catalog differs from native pack identity")
        yield identity, manifest, catalog[0]


@lru_cache(maxsize=1)
def native_extensions():
    from codex_plugin_scanner.guard.runtime.generated_command_catalog_loader import _extension

    with compiled_inventory() as (_, reader, release):
        return tuple(_extension(row) for _, _, row in catalog_rows(reader, release))
