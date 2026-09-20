#!/usr/bin/env python3
"""Validate mutation-test output against a reviewed target baseline."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from importlib import metadata
from pathlib import Path
from typing import Final, cast

if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from scripts.ci.mutation_targets import TARGETS

ROOT = Path(__file__).resolve().parents[2]


@dataclass(frozen=True)
class MutationBaseline:
    """One narrow source target and its approved non-regression floor."""

    target: str
    source_path: str
    minimum_score: float
    expected_total: int
    source_sha256: str
    tool_versions: tuple[tuple[str, str], ...]


BASELINES: Final[dict[str, MutationBaseline]] = {
    "command-model": MutationBaseline(
        target="command-model",
        source_path=TARGETS["command-model"].source_path,
        minimum_score=64.0,
        # The reviewed parser refactor changes the complete inventory from 610 to 588.
        expected_total=588,
        source_sha256="08e5cd246e20bd6e327f77d0986ac37ad89fa1ef6dd42e336addf2dfcd9d721c",
        tool_versions=(("mutmut", "3.7.0"), ("libcst", "1.9.0")),
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
    "skipped",
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


def inventory_errors(baseline: MutationBaseline) -> tuple[str, ...]:
    """Require the reviewed source and generator versions before accepting its count."""

    errors: list[str] = []
    try:
        source_sha256 = hashlib.sha256((ROOT / baseline.source_path).read_bytes()).hexdigest()
    except OSError:
        errors.append("reviewed mutation source is unavailable")
    else:
        if source_sha256 != baseline.source_sha256:
            errors.append("mutation source differs from the reviewed inventory")
    for package, expected in baseline.tool_versions:
        try:
            actual = metadata.version(package)
        except metadata.PackageNotFoundError:
            errors.append(f"reviewed generator {package} is unavailable")
        else:
            if actual != expected:
                errors.append(f"generator {package} differs from reviewed version {expected}")
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
        "expected_total": baseline.expected_total,
        "source_sha256": baseline.source_sha256,
        "tool_versions": dict(baseline.tool_versions),
        "counts": counts,
    }
    print(json.dumps(payload, sort_keys=True))
    errors = validation_errors(baseline, counts) + inventory_errors(baseline)
    for error in errors:
        print(f"mutation gate: {error}")
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
