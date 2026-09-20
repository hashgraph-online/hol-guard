"""Compile reviewed extension definitions into the packaged native program.

Run from the repository root with its locked development environment. The
compiler accepts only package-owned reviewed types; contribution metadata
never supplies an import path to this tool.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.runtime.native_command_program import (
    canonical_program_bytes,
    compile_native_command_program,
)

ROOT = Path(__file__).resolve().parents[1]
ARTIFACT = ROOT / "contracts/extensions/native-command-program.v1.json"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="Reject a missing or stale checked-in artifact.")
    args = parser.parse_args()
    program = compile_native_command_program(BUILT_IN_COMMAND_EXTENSION_REGISTRY)
    encoded = canonical_program_bytes(program) + b"\n"
    if args.check:
        if not ARTIFACT.is_file() or ARTIFACT.read_bytes() != encoded:
            print("Native command program is missing or stale; run scripts/build_native_command_program.py.")
            return 1
    else:
        ARTIFACT.write_bytes(encoded)
    print(
        json.dumps(
            {
                "artifact": str(ARTIFACT.relative_to(ROOT)),
                "program_digest": program["program_digest"],
                "catalog_digest": program["catalog_digest"],
                "bytes": len(encoded),
                "checked": bool(args.check),
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
