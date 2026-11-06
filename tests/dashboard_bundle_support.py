"""Locate files in the built dashboard bundle."""

from __future__ import annotations

from pathlib import Path

CHUNKS_DIR = Path(__file__).parents[1] / "src/codex_plugin_scanner/guard/daemon/static/assets/chunks"

# Rollup appends an 8-character content hash to every chunk file name.
_HASH_SUFFIX = "-????????.js"


def dashboard_chunk(name: str, chunks_dir: Path = CHUNKS_DIR) -> Path:
    """The built chunk for the dashboard module ``name``, whatever its content hash is."""

    matches = sorted(chunks_dir.glob(f"{name}{_HASH_SUFFIX}"))
    assert len(matches) == 1, f"expected one {name} chunk in {chunks_dir}, found {[m.name for m in matches]}"
    return matches[0]
