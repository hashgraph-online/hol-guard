#!/usr/bin/env python3
"""Reject unexplained pytest-node and test-LOC growth in CI."""

from __future__ import annotations

import argparse
import json
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import cast


@dataclass(frozen=True)
class TestSuiteRatchetBaseline:
    """Reviewed upper bounds for the two anti-gaming dimensions collected in every PR."""

    maximum_collected_cases: int
    maximum_test_source_lines: int


def load_baseline(path: Path) -> TestSuiteRatchetBaseline:
    """Load the checked-in baseline with strict schema validation."""

    payload = cast(Mapping[str, object], json.loads(path.read_text(encoding="utf-8")))
    if payload.get("schema_version") != 1:
        raise ValueError("unsupported test-suite ratchet baseline")
    values = {
        "maximum_collected_cases": payload.get("maximum_collected_cases"),
        "maximum_test_source_lines": payload.get("maximum_test_source_lines"),
    }
    for key, value in values.items():
        if not isinstance(value, int) or isinstance(value, bool) or value < 1:
            raise ValueError(f"test-suite ratchet baseline has invalid {key!r}")
    return TestSuiteRatchetBaseline(**cast(dict[str, int], values))


def load_inventory_metrics(path: Path) -> tuple[int, int]:
    """Read only the metrics required for this narrow, always-on ratchet."""

    payload = cast(Mapping[str, object], json.loads(path.read_text(encoding="utf-8")))
    inventory = payload.get("inventory")
    if not isinstance(inventory, Mapping):
        raise ValueError("test inventory is missing inventory metrics")
    collected_cases = inventory.get("collected_cases")
    test_source_lines = payload.get("test_source_lines")
    for key, value in {
        "collected_cases": collected_cases,
        "test_source_lines": test_source_lines,
    }.items():
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise ValueError(f"test inventory has invalid {key!r}")
    return cast(int, collected_cases), cast(int, test_source_lines)


def validation_errors(
    baseline: TestSuiteRatchetBaseline,
    *,
    collected_cases: int,
    test_source_lines: int,
) -> tuple[str, ...]:
    """Report every exceeded bound so maintainers can make one reviewed update."""

    errors: list[str] = []
    if collected_cases > baseline.maximum_collected_cases:
        errors.append(
            f"collected cases grew from {baseline.maximum_collected_cases} to {collected_cases}; "
            "update the reviewed ratchet baseline if this is intentional"
        )
    if test_source_lines > baseline.maximum_test_source_lines:
        errors.append(
            f"test source lines grew from {baseline.maximum_test_source_lines} to {test_source_lines}; "
            "update the reviewed ratchet baseline if this is intentional"
        )
    return tuple(errors)


def main() -> int:
    parser = argparse.ArgumentParser()
    _ = parser.add_argument("--baseline", type=Path, required=True)
    _ = parser.add_argument("--inventory", type=Path, required=True)
    args = parser.parse_args()
    baseline = load_baseline(args.baseline)
    collected_cases, test_source_lines = load_inventory_metrics(args.inventory)
    errors = validation_errors(
        baseline,
        collected_cases=collected_cases,
        test_source_lines=test_source_lines,
    )
    for error in errors:
        print(f"test-suite ratchet: {error}")
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
