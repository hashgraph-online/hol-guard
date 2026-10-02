"""Stage and verify this build's native resources identically on PRs and main.

Cargo has already generated and embedded the program. Staging copies derived
bytes for Python consumers, then validates the compiler and package binding.
No source-tree projection, Git comparison, or later repair PR is required.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compiler", type=Path, required=True)
    parser.add_argument("--changed-from", help=argparse.SUPPRESS)
    args = parser.parse_args()
    sys.path.insert(0, str(ROOT))
    from scripts.build_guard_resources import prepare

    prepare(ROOT, compiler=args.compiler)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
