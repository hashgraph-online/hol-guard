"""Run a pytest shard without rewriting committed fixtures.

Kept as the existing CI entry point. Source-bound tests now evaluate the current
build directly; there is no generation subprocess or fixture restoration phase.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
FRESHNESS_NODE = "tests/test_guard_command_decision_diff.py::test_report_is_exactly_reproducible_and_source_bound"


def main(argv: Sequence[str] | None = None) -> int:
    """Run the assigned tests once while preserving independent fixture bytes."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("shard_file", type=Path)
    parser.add_argument("pytest_args", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    # Fail early for a missing plan; pytest still validates its complete node list.
    args.shard_file.read_text(encoding="utf-8")
    pytest_args = args.pytest_args
    if pytest_args[:1] == ["--"]:
        pytest_args = pytest_args[1:]
    return subprocess.run([sys.executable, "-m", "pytest", *pytest_args], cwd=ROOT, check=False).returncode


if __name__ == "__main__":
    raise SystemExit(main())
