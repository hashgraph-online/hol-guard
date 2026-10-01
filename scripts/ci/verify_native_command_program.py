"""Verify the generated native command program, tolerating pending contributions.

Generated projections are maintainer-owned. A contribution PR that adds or
edits canonical sources legitimately leaves the checked-in program stale, so a
plain ``--check`` would reject an otherwise-valid contribution. This wrapper:

- fresh tree: runs ``build_native_command_program.py --check`` as before
- pending tree (new/edited contribution source): runs the generator without
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
    """Propagate a failed command before later verification stages execute."""
    completed = subprocess.run(command, cwd=ROOT, check=False)
    if completed.returncode:
        raise SystemExit(completed.returncode)


def main() -> int:
    """Choose strict or pending-source validation from a successful comparison."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compiler", required=True)
    parser.add_argument("--changed-from")
    args = parser.parse_args()

    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from detect_pending_extension_regen import (
        ContributionDiffError,
        _contributions_changed,
        catalog_ids,
        contribution_ids,
    )

    pending = sorted(contribution_ids() - catalog_ids())
    try:
        changed = _contributions_changed(args.changed_from) if args.changed_from else []
    except ContributionDiffError as error:
        print(str(error), file=sys.stderr)
        return 1
    command = [
        sys.executable,
        "scripts/build_native_command_program.py",
        "--compiler",
        args.compiler,
    ]
    if args.changed_from and (pending or changed):
        print(
            f"pending contribution regeneration (ids={pending}, changed={changed}); "
            "validating sources by generating instead of checking freshness",
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
