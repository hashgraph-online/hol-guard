"""Run the source-bound report shard with a temporary current projection.

The generated-artifacts guard assigns committed projections to post-merge
automation. PR coverage still validates the original pair before generating
the current source projection, and restores its exact bytes afterward.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from pathlib import Path

FRESHNESS_NODE = "tests/test_guard_command_decision_diff.py::test_report_is_exactly_reproducible_and_source_bound"
ROOT = Path(__file__).resolve().parents[2]


@contextmanager
def current_projection(shard_file: Path) -> Iterator[None]:
    if FRESHNESS_NODE not in shard_file.read_text(encoding="utf-8").splitlines():
        yield
        return

    sys.path.insert(0, str(ROOT))
    from tests.guard_command_decision_diff import REPORT_PATH, canonical_json_bytes, report_framed_sha256

    digest_path = REPORT_PATH.with_name("decision-diff-report.framed-sha256")
    originals = {REPORT_PATH: REPORT_PATH.read_bytes(), digest_path: digest_path.read_bytes()}
    report = json.loads(originals[REPORT_PATH])
    if originals[REPORT_PATH] != canonical_json_bytes(report):
        raise ValueError("checked report is not canonical")
    if originals[digest_path] != (report_framed_sha256(report) + "\n").encode("ascii"):
        raise ValueError("checked report framed digest does not match")
    try:
        subprocess.run([sys.executable, "tests/guard_command_decision_diff.py", "--write"], cwd=ROOT, check=True)
        yield
    finally:
        for path, content in originals.items():
            path.write_bytes(content)
        if any(path.read_bytes() != content for path, content in originals.items()):
            raise RuntimeError("checked report restoration failed")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("shard_file", type=Path)
    parser.add_argument("pytest_args", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    pytest_args = args.pytest_args
    if pytest_args[:1] == ["--"]:
        pytest_args = pytest_args[1:]
    with current_projection(args.shard_file):
        return subprocess.run([sys.executable, "-m", "pytest", *pytest_args], cwd=ROOT, check=False).returncode


if __name__ == "__main__":
    raise SystemExit(main())
