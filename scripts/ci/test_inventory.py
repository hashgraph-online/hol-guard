#!/usr/bin/env python3
"""Emit a stable, machine-readable inventory of the collected pytest suite."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Protocol, cast

import pytest


class _CollectionSession(Protocol):
    items: list[pytest.Item]


@dataclass(frozen=True)
class TestInventory:
    collected_cases: int
    test_functions: int
    test_files: int
    parameterized_cases: int
    marker_counts: dict[str, int]


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


def main() -> int:
    parser = argparse.ArgumentParser()
    _ = parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    payload = json.dumps(asdict(collect_inventory(root)), indent=2, sort_keys=True) + "\n"
    output = cast(Path | None, args.output)
    if output is None:
        print(payload, end="")
    else:
        output.write_text(payload, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
