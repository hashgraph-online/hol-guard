#!/usr/bin/env python3
"""Validate mutation-test output against a reviewed target baseline."""

from __future__ import annotations

import argparse
import json
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Final, cast


@dataclass(frozen=True)
class MutationBaseline:
    """One narrow source target and its approved non-regression floor."""

    target: str
    source_path: str
    minimum_score: float
    expected_total: int


BASELINES: Final[dict[str, MutationBaseline]] = {
    "command-model": MutationBaseline(
        target="command-model",
        source_path="src/codex_plugin_scanner/guard/runtime/command_model.py",
        minimum_score=64.0,
        expected_total=610,
    ),
}

_REQUIRED_COUNTS: Final[tuple[str, ...]] = (
    "killed",
    "survived",
    "total",
    "no_tests",
    "skipped",
    "suspicious",
    "timeout",
    "segfault",
    "check_was_interrupted_by_user",
)
_UNACCEPTABLE_COUNTS: Final[tuple[str, ...]] = (
    "no_tests",
    "suspicious",
    "timeout",
    "segfault",
    "check_was_interrupted_by_user",
)


def load_counts(path: Path) -> dict[str, int]:
    """Load and validate mutmut's machine-readable CI summary."""

    payload = cast(Mapping[str, object], json.loads(path.read_text(encoding="utf-8")))
    counts: dict[str, int] = {}
    for key in _REQUIRED_COUNTS:
        value = payload.get(key)
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise ValueError(f"Mutation summary has an invalid {key!r} value")
        counts[key] = value
    if counts["killed"] + counts["survived"] != counts["total"]:
        raise ValueError("Mutation summary total must equal killed plus survived")
    return counts


def mutation_score(counts: Mapping[str, int]) -> float:
    """Return the percentage of evaluated mutants killed by the test selection."""

    total = counts["total"]
    if total == 0:
        raise ValueError("Mutation summary contains no evaluated mutants")
    return counts["killed"] * 100 / total


def validation_errors(baseline: MutationBaseline, counts: Mapping[str, int]) -> tuple[str, ...]:
    """Return all violated baseline constraints without hiding secondary failures."""

    errors: list[str] = []
    score = mutation_score(counts)
    if counts["total"] != baseline.expected_total:
        errors.append(f"expected {baseline.expected_total} mutants, found {counts['total']}")
    if score < baseline.minimum_score:
        errors.append(f"mutation score {score:.2f}% is below {baseline.minimum_score:.2f}%")
    for key in _UNACCEPTABLE_COUNTS:
        if counts[key]:
            errors.append(f"{key} must be zero, found {counts[key]}")
    return tuple(errors)


def main() -> int:
    parser = argparse.ArgumentParser()
    _ = parser.add_argument("--target", choices=sorted(BASELINES), required=True)
    _ = parser.add_argument(
        "--summary",
        type=Path,
        default=Path("mutants/mutmut-cicd-stats.json"),
        help="Path written by `mutmut export-cicd-stats`.",
    )
    args = parser.parse_args()
    baseline = BASELINES[args.target]
    counts = load_counts(args.summary)
    score = mutation_score(counts)
    payload = {
        "target": baseline.target,
        "source_path": baseline.source_path,
        "score": round(score, 2),
        "minimum_score": baseline.minimum_score,
        "counts": counts,
    }
    print(json.dumps(payload, sort_keys=True))
    errors = validation_errors(baseline, counts)
    for error in errors:
        print(f"mutation gate: {error}")
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
