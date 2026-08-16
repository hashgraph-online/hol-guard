#!/usr/bin/env python3
"""Collect pytest once and emit deterministic duration-balanced shard files."""

from __future__ import annotations

import argparse
import json
import math
import sys
from collections import defaultdict
from collections.abc import Mapping, Sequence
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Protocol, cast

if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from scripts.ci.pytest_duration_manifest import load_duration_manifest, node_id_digest
from scripts.ci.pytest_shard import discover_test_nodes

PLAN_SCHEMA_VERSION = 1
UNKNOWN_NODE_DURATION_SECONDS = 1.0
MAX_UNSPLIT_FILE_TARGET_MULTIPLIER = 1.15


class _Arguments(Protocol):
    shard_count: int
    duration_manifest: Path
    max_manifest_age_days: int
    output_directory: Path


def node_file(node_id: str) -> str:
    """Return and validate the repository-relative file that owns a pytest node."""

    if "\n" in node_id or "\r" in node_id or "\x00" in node_id:
        raise ValueError(f"invalid pytest node id: {node_id!r}")
    path = node_id.split("::", maxsplit=1)[0]
    if not path.startswith("tests/") or not path.endswith(".py"):
        raise ValueError(f"invalid pytest node id: {node_id!r}")
    return path


def estimate_node_durations(node_ids: Sequence[str], durations: Mapping[str, float]) -> dict[str, float]:
    """Map collected node IDs to current estimates with a conservative fallback."""

    known = sorted(
        duration
        for node_id in node_ids
        if (duration := durations.get(node_id_digest(node_id), 0.0)) > 0
    )
    fallback = max(
        UNKNOWN_NODE_DURATION_SECONDS,
        known[(len(known) - 1) // 2] if known else 0.0,
    )
    return {
        node_id: float(durations.get(node_id_digest(node_id), fallback))
        for node_id in node_ids
    }


def _split_file_nodes(
    file_path: str,
    node_ids: Sequence[str],
    estimates: Mapping[str, float],
    target_seconds: float,
) -> list[tuple[str, int, list[str], float]]:
    total = sum(estimates[node_id] for node_id in node_ids)
    split_count = 1
    if total > target_seconds * MAX_UNSPLIT_FILE_TARGET_MULTIPLIER:
        split_count = min(len(node_ids), max(1, math.ceil(total / target_seconds)))

    chunks: list[list[str]] = [[] for _ in range(split_count)]
    loads = [0.0] * split_count
    for node_id in sorted(node_ids, key=lambda node: (-estimates[node], node)):
        index = min(range(split_count), key=lambda item: (loads[item], item))
        chunks[index].append(node_id)
        loads[index] += estimates[node_id]

    return [
        (file_path, index, sorted(chunk), loads[index])
        for index, chunk in enumerate(chunks)
        if chunk
    ]


def build_affinity_node_shards(
    node_ids: Sequence[str],
    shard_count: int,
    durations: Mapping[str, float],
) -> tuple[list[list[str]], list[float]]:
    """Balance by duration while keeping each test file together when practical."""

    nodes = list(node_ids)
    if shard_count < 1:
        raise ValueError("shard_count must be positive")
    if shard_count > len(nodes):
        raise ValueError("shard_count cannot exceed the number of test nodes")
    if len(nodes) != len(set(nodes)):
        raise ValueError("test node ids must be unique")

    estimates = estimate_node_durations(nodes, durations)
    target_seconds = sum(estimates.values()) / shard_count
    by_file: dict[str, list[str]] = defaultdict(list)
    for node_id in nodes:
        by_file[node_file(node_id)].append(node_id)

    groups: list[tuple[str, int, list[str], float]] = []
    for file_path, file_nodes in sorted(by_file.items()):
        groups.extend(_split_file_nodes(file_path, file_nodes, estimates, target_seconds))

    shards: list[list[str]] = [[] for _ in range(shard_count)]
    loads = [0.0] * shard_count
    for file_path, group_index, group_nodes, group_load in sorted(
        groups,
        key=lambda group: (-group[3], group[0], group[1]),
    ):
        _ = file_path, group_index
        shard_index = min(range(shard_count), key=lambda index: (loads[index], index))
        shards[shard_index].extend(group_nodes)
        loads[shard_index] += group_load

    if any(not shard for shard in shards):
        raise ValueError("every pytest shard must contain at least one test node")
    for shard in shards:
        shard.sort()

    flattened = [node_id for shard in shards for node_id in shard]
    if len(flattened) != len(nodes) or set(flattened) != set(nodes):
        raise ValueError("pytest shard plan must cover every collected node exactly once")
    return shards, loads


def write_shard_plan(
    output_directory: Path,
    *,
    shards: Sequence[Sequence[str]],
    estimated_loads: Sequence[float],
    manifest_used: bool,
) -> None:
    """Write one response file per shard plus reviewable plan metadata."""

    if len(shards) != len(estimated_loads) or not shards:
        raise ValueError("shards and estimated loads must be non-empty and aligned")
    output_directory.mkdir(parents=True, exist_ok=True)
    width = max(2, len(str(len(shards) - 1)))
    for index, shard in enumerate(shards):
        path = output_directory / f"shard-{index:0{width}d}.txt"
        path.write_text("\n".join(shard) + "\n", encoding="utf-8")

    metadata = {
        "schema_version": PLAN_SCHEMA_VERSION,
        "shard_count": len(shards),
        "node_count": sum(len(shard) for shard in shards),
        "duration_manifest_used": manifest_used,
        "estimated_load_seconds": [round(load, 6) for load in estimated_loads],
        "node_counts": [len(shard) for shard in shards],
        "file_counts": [len({node_file(node_id) for node_id in shard}) for shard in shards],
    }
    (output_directory / "plan.json").write_text(
        json.dumps(metadata, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )


def _load_current_durations(path: Path, max_age_days: int) -> tuple[dict[str, float], bool]:
    try:
        return (
            load_duration_manifest(
                path,
                now=datetime.now(timezone.utc),
                max_age=timedelta(days=max_age_days),
            ),
            True,
        )
    except (OSError, ValueError) as exc:
        print(
            f"pytest duration manifest unavailable; using deterministic equal-weight planning: {exc}",
            file=sys.stderr,
        )
        return {}, False


def main() -> int:
    parser = argparse.ArgumentParser()
    _ = parser.add_argument("--shard-count", type=int, required=True)
    _ = parser.add_argument("--duration-manifest", type=Path, required=True)
    _ = parser.add_argument("--max-manifest-age-days", type=int, default=28)
    _ = parser.add_argument("--output-directory", type=Path, required=True)
    args = cast(_Arguments, cast(object, parser.parse_args()))

    root = Path(__file__).resolve().parents[2]
    durations, manifest_used = _load_current_durations(
        args.duration_manifest,
        args.max_manifest_age_days,
    )
    nodes = discover_test_nodes(root)
    shards, loads = build_affinity_node_shards(nodes, args.shard_count, durations)
    write_shard_plan(
        args.output_directory,
        shards=shards,
        estimated_loads=loads,
        manifest_used=manifest_used,
    )
    print(
        json.dumps(
            {
                "shards": len(shards),
                "nodes": len(nodes),
                "manifest_used": manifest_used,
                "estimated_min_seconds": round(min(loads), 3),
                "estimated_max_seconds": round(max(loads), 3),
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
