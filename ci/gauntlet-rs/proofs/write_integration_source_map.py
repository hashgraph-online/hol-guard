"""Write one exclusive path-to-SHA map for an exact Git controller proof.

The host Rust reader must still verify every mapped blob at the outside commit.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys

from build_controller_install_fixture import WORKSPACE, source_hashes


def main(destination: Path) -> None:
    if not destination.is_absolute() or destination.exists() or destination.is_symlink():
        raise ValueError("new absolute source-map destination required")
    hashes = source_hashes()
    for name, expected in hashes.items():
        path = WORKSPACE / name
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"source-map file is not ordinary: {name}")
        if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise ValueError(f"source-map file differs from integration pin: {name}")
    with destination.open("x", encoding="utf-8") as stream:
        stream.write(json.dumps(hashes, sort_keys=True, separators=(",", ":")) + "\n")
    print(f"wrote {len(hashes)} exact source hashes to {destination}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: write_integration_source_map.py EXACT_OUTPUT_JSON")
    main(Path(sys.argv[1]))
