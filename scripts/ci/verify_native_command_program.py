"""Stage and strictly verify current native projections on every build event.

Cargo compiles the authored command/MCP sources into the native binary before
this step. Tracked descriptors and public catalogs retain their existing
locations and maintainer publication flow. A stale committed projection is not
an instruction to skip tests or rebuild Rust after generating test fixtures.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _run(command: list[str]) -> None:
    """Stop immediately on invalid sources, a stale compiler, or a bad output."""
    completed = subprocess.run(command, cwd=ROOT, check=False)
    if completed.returncode:
        raise SystemExit(completed.returncode)


def main() -> int:
    """Stage current projections, then reject any source, compiler or embedded-program mismatch."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compiler", required=True)
    parser.add_argument(
        "--changed-from",
        help="Accepted for existing callers; validation always covers the complete current source tree.",
    )
    args = parser.parse_args()
    if sys.platform == "win32" and not Path(args.compiler).suffix:
        args.compiler += ".exe"
    command = [sys.executable, "scripts/build_native_command_program.py", "--compiler", args.compiler]
    _run(command)
    _run([*command, "--check"])
    # Packaging uses the exact compiler just validated, including cross-target
    # and Windows paths, rather than performing a second host/debug build.
    environment_file = os.environ.get("GITHUB_ENV")
    if environment_file:
        compiler = str(Path(args.compiler).resolve(strict=True))
        if "\n" in compiler or "\r" in compiler:
            raise ValueError("invalid compiler path for workflow environment")
        with Path(environment_file).open("a", encoding="utf-8") as handle:
            handle.write(f"HOL_GUARD_BUILD_SOURCE_COMPILER={compiler}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
