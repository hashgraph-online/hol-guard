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
PREPARATION_TIMEOUT_SECONDS = 300


def _prepare(arguments: Sequence[str]) -> int:
    try:
        return subprocess.run(arguments, cwd=ROOT, check=False, timeout=PREPARATION_TIMEOUT_SECONDS).returncode
    except subprocess.TimeoutExpired:
        print(f"Projection preparation timed out after {PREPARATION_TIMEOUT_SECONDS}s: {arguments[1]}", file=sys.stderr)
        return 124


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
        prepared = _prepare(
            [
                sys.executable,
                "scripts/ci/verify_native_command_program.py",
                "--compiler",
                compiler,
            ],
        )
        if prepared:
            return prepared
        # Directory preparation needs runtime validation dependencies, available
        # in the coverage environment but not in isolated wheel builds.
        for script in ("export_extension_directory.py", "render_command_extension_directory.py"):
            for arguments in ([], ["--check"]):
                prepared = _prepare([sys.executable, f"scripts/{script}", *arguments])
                if prepared:
                    return prepared
    pytest_args = args.pytest_args
    if pytest_args[:1] == ["--"]:
        pytest_args = pytest_args[1:]
    return subprocess.run([sys.executable, "-m", "pytest", *pytest_args], cwd=ROOT, check=False).returncode


if __name__ == "__main__":
    raise SystemExit(main())
