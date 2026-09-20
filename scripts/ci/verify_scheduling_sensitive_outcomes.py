"""Require successful execution of the untraced workspace-admission cases."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from xml.etree import ElementTree

CASE_CLASS = "tests.test_native_policy_snapshot_default_capture_worker"
CASE_NAME = "test_default_worker_admits_workspace_after_startup_status_writes"
REQUIRED_CASES = frozenset(f"{CASE_NAME}[{variant}]" for variant in ("none", "twice", "continuous"))
_MAX_REPORT_BYTES = 512 * 1024


class _Arguments(argparse.Namespace):
    junit: Path = Path()


def validate_required_cases(data: bytes) -> None:
    """Reject missing, duplicate, skipped, failed, or erroneous exact cases."""
    if not data or len(data) > _MAX_REPORT_BYTES:
        raise ValueError("scheduling_sensitive_report_invalid")
    try:
        root = ElementTree.fromstring(data)
    except ElementTree.ParseError as error:
        raise ValueError("scheduling_sensitive_report_invalid") from error
    cases = [case for case in root.iter("testcase") if case.get("classname") == CASE_CLASS]
    if len(cases) != len(REQUIRED_CASES) or frozenset(case.get("name") for case in cases) != REQUIRED_CASES:
        raise ValueError("scheduling_sensitive_cases_incomplete")
    if any(case.find(outcome) is not None for case in cases for outcome in ("skipped", "failure", "error")):
        raise ValueError("scheduling_sensitive_cases_not_passed")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    _ = parser.add_argument("--junit", type=Path, required=True)
    args = _Arguments()
    _ = parser.parse_args(argv, namespace=args)
    try:
        with args.junit.open("rb") as source:
            data = source.read(_MAX_REPORT_BYTES + 1)
        validate_required_cases(data)
    except (OSError, ValueError):
        print(json.dumps({"schema": "guard.scheduling-sensitive-outcomes.v1", "passed": False}), file=sys.stderr)
        return 1
    print(json.dumps({"schema": "guard.scheduling-sensitive-outcomes.v1", "passed": True, "required_cases": 3}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
