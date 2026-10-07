"""Prepare complete source projections and run an assigned pytest shard.

Artifact downloads overlay checkout files; they cannot represent descriptors
deleted by source preparation. Reuse the source verifier in native CI so orphan
legacy descriptors are removed before directory and trust consumers run.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def main(argv: Sequence[str] | None = None) -> int:
    """Reconcile downloaded projections before running the assigned tests once."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("shard_file", type=Path)
    parser.add_argument("pytest_args", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    # Fail early for a missing plan; pytest still validates its complete node list.
    args.shard_file.read_text(encoding="utf-8")
    compiler = os.environ.get("HOL_GUARD_NATIVE_SOURCE_COMPILER")
    if compiler:
        prepared = subprocess.run(
            [
                sys.executable,
                "scripts/ci/verify_native_command_program.py",
                "--compiler",
                compiler,
            ],
            cwd=ROOT,
            check=False,
        )
        if prepared.returncode:
            return prepared.returncode
    pytest_args = args.pytest_args
    if pytest_args[:1] == ["--"]:
        pytest_args = pytest_args[1:]
    return subprocess.run([sys.executable, "-m", "pytest", *pytest_args], cwd=ROOT, check=False).returncode


if __name__ == "__main__":
    raise SystemExit(main())
