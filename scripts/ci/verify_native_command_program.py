"""Verify the generated native command program, tolerating pending contributions.

Generated projections are maintainer-owned. A contribution PR that adds or
edits canonical sources legitimately leaves the checked-in program stale, so a
plain ``--check`` would reject an otherwise-valid contribution. This wrapper:

- fresh tree: runs ``build_native_command_program.py --check`` as before
- pending tree (new/edited contribution source): runs the generator without
  ``--check``, retains the generated workspace projections, and rebuilds the
  native binaries so subsequent proofs and packaging use the same program
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

def _rebuild_command(compiler: str) -> list[str]:
    path = ROOT / compiler
    relative = path.resolve().relative_to((ROOT / "rust" / "target").resolve())
    parts = relative.parts
    if len(parts) not in (2, 3) or parts[-2] not in ("debug", "release"):
        raise ValueError("compiler must be in rust/target/[target/]debug or release")
    command = ["cargo", "build", "--manifest-path", "rust/Cargo.toml", "--locked",
               "-p", "hol-guard-runtime", "-p", "guard-command",
               "--bin", "hol-guard-runtime", "--bin", "guard-command-source"]
    if parts[-2] == "release":
        command.append("--release")
    if len(parts) == 3:
        command.extend(["--target", parts[0]])
    return command


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
        REGEN_INPUT_PREFIXES,
        ContributionDiffError,
        _contributions_changed,
        catalog_ids,
        contribution_ids,
        pr_diff_paths,
        regen_artifacts_absent_from_diff,
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
    diff = pr_diff_paths()
    if args.changed_from and diff is None and not (pending or changed):
        # Diff unresolvable and no contribution sources to validate: defer
        # freshness to post-merge regen verification on main.
        return 0
    if diff is not None and args.changed_from:
        carries = not regen_artifacts_absent_from_diff(diff)
        inputs = any(path.startswith(REGEN_INPUT_PREFIXES) for path in diff)
        if carries:
            # The PR carries regenerated projections; verify them strictly.
            _run([*command, "--check"])
            return 0
        if not pending and not inputs:
            print(
                "PR carries neither generated projections nor their inputs; "
                "any checked-in drift is inherited from main and regen-owned — "
                "deferring freshness verification to extension-artifact-regen",
                file=sys.stderr,
            )
            return 0
        # Inputs changed without carried artifacts: validate the sources by
        # generating, leaving the checked-in projections to post-merge regen.
        print(
            f"pending artifact regeneration (ids={pending}, inputs changed); "
            "validating sources by generating instead of checking freshness",
            file=sys.stderr,
        )
        rebuild = _rebuild_command(args.compiler)
        _run(command)
        _run(rebuild)
        _run([*command, "--check"])
        return 0
    _run([*command, "--check"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
