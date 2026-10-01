"""Verify the generated native command program, tolerating pending contributions.

Generated projections are maintainer-owned. A PR that changes projection
inputs — contribution sources, the Rust compiler, trust map, or generator
scripts — legitimately leaves the checked-in program stale, so a plain
``--check`` would reject an otherwise-valid change. This wrapper:

- fresh tree: runs ``build_native_command_program.py --check`` as before
- pending tree (new/edited projection input): runs the generator without
  ``--check`` to validate that the sources compile, then restores generated
  paths so later steps see the checked-in state
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
GENERATED_PATHS = (
    "contracts/extensions",
    "contributions/extensions",
    "src/codex_plugin_scanner/guard/contracts/data/extensions",
    "src/codex_plugin_scanner/guard/extension_builder",
)


def _run(command: list[str]) -> None:
    completed = subprocess.run(command, cwd=ROOT, check=False)
    if completed.returncode:
        raise SystemExit(completed.returncode)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compiler", required=True)
    parser.add_argument("--changed-from")
    args = parser.parse_args()

    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from detect_pending_extension_regen import (
        _regen_inputs_changed,
        catalog_ids,
        contribution_ids,
    )

    pending = sorted(contribution_ids() - catalog_ids())
    changed = _regen_inputs_changed(args.changed_from) if args.changed_from else []
    command = [
        sys.executable,
        "scripts/build_native_command_program.py",
        "--compiler",
        args.compiler,
    ]
    if args.changed_from and (pending or changed):
        print(
            f"pending projection regeneration (ids={pending}, changed={changed}); "
            "validating inputs by generating instead of checking freshness",
            file=sys.stderr,
        )
        _run(command)
        _run(["git", "checkout", "--", *GENERATED_PATHS])
        _run(["git", "clean", "-fdq", "--", *GENERATED_PATHS])
        return 0
    _run([*command, "--check"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
