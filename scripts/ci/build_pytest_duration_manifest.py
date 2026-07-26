#!/usr/bin/env python3
"""Create a validated duration manifest from pytest shard artifacts."""

from __future__ import annotations

import argparse
import sys
from datetime import datetime
from pathlib import Path
from typing import Protocol, cast

if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from scripts.ci.pytest_duration_manifest import merge_duration_reports, write_duration_manifest


class _Arguments(Protocol):
    output: Path
    observed_at: str
    reports: list[Path]


def main() -> int:
    parser = argparse.ArgumentParser()
    _ = parser.add_argument("--output", type=Path, required=True)
    _ = parser.add_argument("--observed-at", required=True)
    _ = parser.add_argument("reports", nargs="+", type=Path)
    args = cast(_Arguments, cast(object, parser.parse_args()))
    try:
        observed_at = datetime.fromisoformat(args.observed_at.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("--observed-at must be ISO-8601 with a timezone") from exc
    write_duration_manifest(args.output, merge_duration_reports(args.reports), observed_at)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
