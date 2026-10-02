"""Verify committed native projections before either a PR or main can pass.

Source and generated outputs must merge together. Normal callers always run
read-only freshness verification, even for source-only PRs. The explicit
--prepare option is retained for local preview builds, not required CI gates.
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
    command = [
        "cargo",
        "build",
        "--manifest-path",
        "rust/Cargo.toml",
        "--locked",
        "-p",
        "hol-guard-runtime",
        "-p",
        "guard-command",
        "--bin",
        "hol-guard-runtime",
        "--bin",
        "guard-command-source",
    ]
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
    """Require committed freshness unless local preparation is explicitly requested."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compiler", required=True)
    parser.add_argument("--changed-from")
    parser.add_argument(
        "--prepare",
        action="store_true",
        help="Prepare a local preview; never use this mode as a merge gate.",
    )
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
    if args.prepare and args.changed_from and (pending or changed):
        print(
            f"pending contribution regeneration (ids={pending}, changed={changed}); "
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
