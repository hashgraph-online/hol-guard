"""Stage and strictly verify current native projections on every build event.

Cargo compiles the authored command/MCP sources into the native binary before
this step. Tracked descriptors and public catalogs retain their existing
locations and maintainer publication flow. A stale committed projection is not
an instruction to skip tests or rebuild Rust after generating test fixtures.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _run(command: list[str]) -> None:
    """Stop immediately on invalid sources, a stale compiler, or a bad output."""
    completed = subprocess.run(command, cwd=ROOT, check=False)
    if completed.returncode:
        raise SystemExit(completed.returncode)


def _prepare_directory(compiler: Path) -> Path:
    """Keep one private inventory alive across all five unchanged checks."""
    scripts = str(ROOT / "scripts")
    sys.path.insert(0, scripts)
    try:
        import build_native_command_program as program
        import prepare_extension_directory as directory
        from native_projection_inventory import ProjectionInventory

        with ProjectionInventory(ROOT, compiler) as inventory:
            arguments = ["--compiler", str(inventory.compiler)]
            for phase, extra in (
                ("public-descriptors", ["--check-public-descriptors"]),
                ("command-build", []),
                ("command-check", ["--check"]),
            ):
                started = time.monotonic()
                inventory.validate()
                result = program.main([*arguments, *extra], inventory=inventory)
                if result:
                    raise SystemExit(result)
                inventory.validate()
                print(f"Projection preparation {phase} completed in {time.monotonic() - started:.3f}s", flush=True)
            for check in (False, True):
                started = time.monotonic()
                inventory.validate()
                print(
                    json.dumps(
                        directory.prepare(inventory.compiler, check=check, root=ROOT, inventory=inventory),
                        sort_keys=True,
                    ),
                    flush=True,
                )
                inventory.validate()
                phase = "directory-check" if check else "directory-build"
                print(f"Projection preparation {phase} completed in {time.monotonic() - started:.3f}s", flush=True)
        return inventory.compiler
    finally:
        sys.path.remove(scripts)


def main(argv: list[str] | None = None) -> int:
    """Stage current projections, then reject any source, compiler or embedded-program mismatch."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compiler", required=True)
    parser.add_argument(
        "--prepare-directory", action="store_true", help="Prepare and check directory outputs in this invocation."
    )
    parser.add_argument(
        "--changed-from",
        help="Accepted for existing callers; validation always covers the complete current source tree.",
    )
    args = parser.parse_args(argv)
    if sys.platform == "win32" and not Path(args.compiler).suffix:
        args.compiler += ".exe"
    prepared_compiler = None
    if args.prepare_directory:
        prepared_compiler = _prepare_directory(Path(args.compiler))
    else:
        command = [sys.executable, "scripts/build_native_command_program.py", "--compiler", args.compiler]
        # Check Git blobs first; scratch regeneration cannot repair missing PR inputs.
        _run([*command, "--check-public-descriptors"])
        _run(command)
        _run([*command, "--check"])
    # Packaging uses the exact compiler just validated, including cross-target
    # and Windows paths, rather than performing a second host/debug build.
    environment_file = os.environ.get("GITHUB_ENV")
    if environment_file:
        compiler = str(prepared_compiler if prepared_compiler is not None else Path(args.compiler).resolve(strict=True))
        if "\n" in compiler or "\r" in compiler:
            raise ValueError("invalid compiler path for workflow environment")
        with Path(environment_file).open("a", encoding="utf-8") as handle:
            handle.write(f"HOL_GUARD_BUILD_SOURCE_COMPILER={compiler}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
