#!/usr/bin/env python3
"""Emit a stable, machine-readable inventory of the collected pytest suite."""

from __future__ import annotations

import argparse
import gzip
import json
import sys
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Protocol, cast

import pytest

if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))


class _CollectionSession(Protocol):
    items: list[pytest.Item]


@dataclass(frozen=True)
class TestInventory:
    collected_cases: int
    test_functions: int
    test_files: int
    parameterized_cases: int
    marker_counts: dict[str, int]


@dataclass(frozen=True)
class DurationSummary:
    """The privacy-preserving duration evidence available to the inventory job."""

    known_node_count: int
    predicted_runtime_seconds: float
    observed_at: str


@dataclass(frozen=True)
class TestSuiteMetrics:
    """Reviewable test-suite health data that cannot hide corpus work in node counts."""

    inventory: TestInventory
    test_source_lines: int
    product_source_lines: int
    test_to_product_loc_ratio: float
    protected_invariant_count: int
    corpus_records: int
    property_examples: int
    duration: DurationSummary | None
    mutation_score: None = None
    branch_coverage: None = None
    flake_rate: None = None


class _NodeCollector:
    def __init__(self) -> None:
        self.items: list[pytest.Item] = []

    def pytest_collection_finish(self, session: _CollectionSession) -> None:
        self.items = list(session.items)


def test_function_id(nodeid: str) -> str:
    """Normalize a parameterized node id to its owning function."""
    return nodeid.split("[", maxsplit=1)[0]


def build_inventory(
    node_ids: Sequence[str],
    marker_names_by_node: Mapping[str, Sequence[str]],
) -> TestInventory:
    unique_functions = {test_function_id(nodeid) for nodeid in node_ids}
    test_files = {nodeid.split("::", maxsplit=1)[0] for nodeid in node_ids}
    marker_counts: Counter[str] = Counter()
    for nodeid in node_ids:
        marker_counts.update(set(marker_names_by_node.get(nodeid, ())))
    return TestInventory(
        collected_cases=len(node_ids),
        test_functions=len(unique_functions),
        test_files=len(test_files),
        parameterized_cases=len(node_ids) - len(unique_functions),
        marker_counts=dict(sorted(marker_counts.items())),
    )


def collect_inventory(root: Path) -> TestInventory:
    collector = _NodeCollector()
    result = pytest.main(
        [str(root / "tests"), "--collect-only", "-p", "no:terminal", "--validate-test-invariants"],
        plugins=[collector],
    )
    if result != pytest.ExitCode.OK:
        raise RuntimeError(f"pytest collection failed with exit code {result}")
    node_ids = [item.nodeid for item in collector.items]
    markers = {item.nodeid: tuple(marker.name for marker in item.iter_markers()) for item in collector.items}
    return build_inventory(node_ids, markers)


def count_python_source_lines(root: Path) -> int:
    """Count source lines deterministically without including generated environments."""

    return sum(
        len(path.read_text(encoding="utf-8").splitlines())
        for path in sorted(root.rglob("*.py"))
        if "__pycache__" not in path.parts
    )


def load_duration_summary(path: Path) -> DurationSummary | None:
    """Read manifest aggregates while preserving hashed per-node identities."""

    if not path.is_file():
        return None
    raw = gzip.decompress(path.read_bytes()) if path.suffix == ".gz" else path.read_bytes()
    payload = cast(object, json.loads(raw))
    if not isinstance(payload, dict):
        raise ValueError("pytest duration manifest must be an object")
    observed_at = payload.get("observed_at")
    durations = payload.get("node_durations_seconds")
    if not isinstance(observed_at, str) or not isinstance(durations, dict):
        raise ValueError("pytest duration manifest is missing summary fields")
    values = tuple(durations.values())
    if not all(isinstance(value, (int, float)) and not isinstance(value, bool) for value in values):
        raise ValueError("pytest duration manifest contains an invalid duration")
    return DurationSummary(
        known_node_count=len(values),
        predicted_runtime_seconds=round(sum(float(value) for value in values), 3),
        observed_at=observed_at,
    )


def corpus_record_count() -> int:
    """Count corpus work outside pytest parametrization so node reductions stay reviewable."""

    from tests.guard_command_corpus import iter_adversarial_corpus, iter_benign_corpus
    from tests.guard_copilot_hook_command_corpus import (
        COPILOT_ENCODED_EXEC_DENY_CASES,
        COPILOT_NODE_DELETE_DENY_CASES,
    )
    from tests.guard_seeded_faults import PARSER_SEEDED_FAULTS
    from tests.test_guard_action_lattice import ACTION_LATTICE_PAIR_CASES
    from tests.test_guard_command_critical_floors import (
        CRITICAL_COMMAND_FLOORS,
        CRITICAL_NEAR_MISS_COMMANDS,
    )
    from tests.test_guard_command_specialized_variants import SPECIALIZED_SAFE_VARIANT_CASES
    from tests.test_guard_data_flow import BENIGN_DATA_FLOW_CASES, MALICIOUS_DATA_FLOW_CASES
    from tests.test_guard_github_command_capabilities import GITHUB_CAPABILITY_CASES, GITHUB_REVIEW_FLOORS
    from tests.test_guard_github_command_capability_edges import (
        PR_MERGE_ADMIN_CAPABILITY_CASES,
        UNRELATED_DYNAMIC_COMMAND_CASES,
    )
    from tests.test_guard_js_semver_phase11 import (
        SEMVER_OR_CLAUSE_CASES,
        SEMVER_ORDINARY_RANGE_CASES,
        SEMVER_PRERELEASE_BASE_CASES,
        SEMVER_SUPPORTED_RANGE_CASES,
        SEMVER_ZERO_MAJOR_CASES,
    )
    from tests.test_guard_package_shims import PACKAGE_SHIM_GUARD_CASES
    from tests.test_guard_risk import (
        ENCODED_EXEC_PIPELINE_CASES,
        LOCAL_COMPOSE_SAFE_CASES,
        LOCAL_SHELL_RISK_CASES,
        MUTATING_PYTHON_MODULE_DENY_CASES,
        SENSITIVE_DOCKER_DENY_CASES,
    )
    from tests.test_guard_runtime import COPILOT_NATIVE_DENY_COMMANDS

    return (
        sum(1 for _ in iter_benign_corpus())
        + sum(1 for _ in iter_adversarial_corpus())
        + len(COPILOT_ENCODED_EXEC_DENY_CASES)
        + len(COPILOT_NODE_DELETE_DENY_CASES)
        + len(PARSER_SEEDED_FAULTS)
        + len(ACTION_LATTICE_PAIR_CASES)
        + len(CRITICAL_COMMAND_FLOORS)
        + len(CRITICAL_NEAR_MISS_COMMANDS)
        + len(GITHUB_REVIEW_FLOORS)
        + len(GITHUB_CAPABILITY_CASES)
        + len(PR_MERGE_ADMIN_CAPABILITY_CASES)
        + len(UNRELATED_DYNAMIC_COMMAND_CASES)
        + len(SPECIALIZED_SAFE_VARIANT_CASES)
        + len(PACKAGE_SHIM_GUARD_CASES)
        + len(ENCODED_EXEC_PIPELINE_CASES)
        + len(SEMVER_ORDINARY_RANGE_CASES)
        + len(SEMVER_OR_CLAUSE_CASES)
        + len(SEMVER_PRERELEASE_BASE_CASES)
        + len(SEMVER_SUPPORTED_RANGE_CASES)
        + len(SEMVER_ZERO_MAJOR_CASES)
        + len(COPILOT_NATIVE_DENY_COMMANDS)
        + len(BENIGN_DATA_FLOW_CASES)
        + len(MALICIOUS_DATA_FLOW_CASES)
        + len(LOCAL_COMPOSE_SAFE_CASES)
        + len(LOCAL_SHELL_RISK_CASES)
        + len(MUTATING_PYTHON_MODULE_DENY_CASES)
        + len(SENSITIVE_DOCKER_DENY_CASES)
    )


def build_suite_metrics(root: Path, inventory: TestInventory) -> TestSuiteMetrics:
    """Build the single CI report used to review count, LOC, corpus, and runtime evidence."""

    test_source_lines = count_python_source_lines(root / "tests")
    product_source_lines = count_python_source_lines(root / "src")
    if product_source_lines == 0:
        raise ValueError("product source line count must be positive")
    from tests.guard_test_invariants import TEST_INVARIANTS

    return TestSuiteMetrics(
        inventory=inventory,
        test_source_lines=test_source_lines,
        product_source_lines=product_source_lines,
        test_to_product_loc_ratio=round(test_source_lines / product_source_lines, 4),
        protected_invariant_count=len(TEST_INVARIANTS),
        corpus_records=corpus_record_count(),
        property_examples=0,
        duration=load_duration_summary(root / "ci" / "pytest-duration-manifest.json.gz"),
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    _ = parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    payload = json.dumps(asdict(build_suite_metrics(root, collect_inventory(root))), indent=2, sort_keys=True) + "\n"
    output = cast(Path | None, args.output)
    if output is None:
        print(payload, end="")
    else:
        output.write_text(payload, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
