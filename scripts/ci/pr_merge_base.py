"""Resolve a PR merge checkout's base without attributing newer base work to its author."""

from __future__ import annotations

import argparse
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def comparison_base(head: str, merge: str, *, root: Path = ROOT) -> str:
    """Require the exact event merge and head before returning its first parent."""
    if not all(re.fullmatch(r"[0-9a-f]{40}", sha) for sha in (head, merge)):
        raise ValueError("Expected full GitHub commit SHAs, not branch names or options.")
    result = subprocess.run(
        ["git", "-C", str(root), "rev-list", "--parents", "-n", "1", "HEAD"],
        capture_output=True,
        text=True,
        check=True,
        timeout=30,
    )
    parents = result.stdout.split()
    if len(parents) != 3 or parents[0] != merge or parents[2] != head:
        raise ValueError("Checkout is not the expected two-parent PR merge; refusing an ambiguous comparison.")
    if not re.fullmatch(r"[0-9a-f]{40}", parents[1]):
        raise ValueError("Invalid comparison parent.")
    return parents[1]


def main() -> int:
    """Print the base SHA for the existing strict source/fixture binding validator."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--head", required=True)
    parser.add_argument("--merge", required=True)
    args = parser.parse_args()
    try:
        print(comparison_base(args.head, args.merge))
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
