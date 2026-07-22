#!/usr/bin/env python3
"""Select a deterministic, balanced shard of pytest files."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Protocol, cast

import pytest


class _CollectionSession(Protocol):
    items: list[pytest.Item]


class _Arguments(Protocol):
    shard_count: int
    shard_index: int
    granularity: str


class _NodeCollector:
    def __init__(self) -> None:
        self.node_ids: list[str] = []

    def pytest_collection_finish(self, session: _CollectionSession) -> None:
        self.node_ids = sorted(item.nodeid for item in session.items)


def discover_test_files(root: Path) -> list[Path]:
    return sorted(path for path in (root / "tests").rglob("test_*.py") if path.is_file())


def build_test_shards(root: Path, shard_count: int) -> list[list[Path]]:
    if shard_count < 1:
        raise ValueError("shard_count must be positive")

    files = discover_test_files(root)
    if shard_count > len(files):
        raise ValueError("shard_count cannot exceed the number of test files")

    shards: list[list[Path]] = [[] for _ in range(shard_count)]
    weights = [0] * shard_count
    weighted_files = sorted(
        ((path.stat().st_size, path) for path in files),
        key=lambda item: (-item[0], item[1].as_posix()),
    )
    for weight, path in weighted_files:
        shard_index = min(range(shard_count), key=lambda index: (weights[index], index))
        shards[shard_index].append(path)
        weights[shard_index] += weight

    for shard in shards:
        shard.sort()
    return shards


def discover_test_nodes(root: Path) -> list[str]:
    collector = _NodeCollector()
    result = pytest.main(
        [str(root / "tests"), "--collect-only", "-p", "no:terminal"],
        plugins=[collector],
    )
    if result != pytest.ExitCode.OK:
        raise RuntimeError(f"pytest collection failed with exit code {result}")
    return collector.node_ids


def build_node_shards(node_ids: list[str], shard_count: int) -> list[list[str]]:
    if shard_count < 1:
        raise ValueError("shard_count must be positive")
    if shard_count > len(node_ids):
        raise ValueError("shard_count cannot exceed the number of test nodes")
    ordered = sorted(node_ids)
    return [ordered[index::shard_count] for index in range(shard_count)]


def select_test_files(root: Path, shard_index: int, shard_count: int) -> list[Path]:
    if shard_index < 0 or shard_index >= shard_count:
        raise ValueError("shard_index must be between zero and shard_count - 1")
    return build_test_shards(root, shard_count)[shard_index]


def main() -> int:
    parser = argparse.ArgumentParser()
    _ = parser.add_argument("--shard-count", type=int, required=True)
    _ = parser.add_argument("--shard-index", type=int, required=True)
    _ = parser.add_argument("--granularity", choices=("file", "node"), default="file")
    args = cast(_Arguments, cast(object, parser.parse_args()))

    root = Path(__file__).resolve().parents[2]
    if args.granularity == "node":
        shards = build_node_shards(discover_test_nodes(root), args.shard_count)
        if args.shard_index < 0 or args.shard_index >= args.shard_count:
            raise ValueError("shard_index must be between zero and shard_count - 1")
        for node_id in shards[args.shard_index]:
            print(node_id)
    else:
        for path in select_test_files(root, args.shard_index, args.shard_count):
            print(path.relative_to(root).as_posix())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
