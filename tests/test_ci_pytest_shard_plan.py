from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.ci.build_pytest_shard_plan import (
    build_affinity_node_shards,
    node_file,
    write_shard_plan,
)
from scripts.ci.pytest_duration_manifest import node_id_digest


def _durations(nodes: list[str], *, seconds: float = 1.0) -> dict[str, float]:
    return {node_id_digest(node_id): seconds for node_id in nodes}


def test_affinity_plan_covers_every_node_once_and_is_deterministic() -> None:
    nodes = [
        f"tests/test_{file_index}.py::test_{test_index}"
        for file_index in range(8)
        for test_index in range(8)
    ]
    durations = _durations(nodes)

    first, first_loads = build_affinity_node_shards(nodes, 4, durations)
    second, second_loads = build_affinity_node_shards(nodes, 4, durations)

    assert first == second
    assert first_loads == second_loads
    flattened = [node_id for shard in first for node_id in shard]
    assert sorted(flattened) == sorted(nodes)
    assert len(flattened) == len(set(flattened))
    owning_shards = {
        file_path: {
            shard_index
            for shard_index, shard in enumerate(first)
            if any(node_file(node_id) == file_path for node_id in shard)
        }
        for file_path in {node_file(node_id) for node_id in nodes}
    }
    assert all(len(shard_indexes) == 1 for shard_indexes in owning_shards.values())


def test_affinity_plan_splits_only_an_oversized_file() -> None:
    large = [f"tests/test_large.py::test_{index}" for index in range(24)]
    small = [f"tests/test_small_{index}.py::test_one" for index in range(6)]
    nodes = large + small
    durations = _durations(nodes)

    shards, loads = build_affinity_node_shards(nodes, 6, durations)

    large_owners = {
        shard_index
        for shard_index, shard in enumerate(shards)
        if any(node_file(node_id) == "tests/test_large.py" for node_id in shard)
    }
    assert 1 < len(large_owners) < 6
    assert max(loads) - min(loads) <= 1.0


def test_affinity_plan_rejects_duplicate_or_invalid_nodes() -> None:
    with pytest.raises(ValueError, match="unique"):
        build_affinity_node_shards(
            ["tests/test_a.py::test_a", "tests/test_a.py::test_a"],
            1,
            {},
        )
    with pytest.raises(ValueError, match="invalid pytest node"):
        build_affinity_node_shards(["outside/test_a.py::test_a"], 1, {})
    with pytest.raises(ValueError, match="invalid pytest node"):
        build_affinity_node_shards(["tests/test_a.py::test_a\ninjected"], 1, {})


def test_write_shard_plan_emits_response_files_and_metadata(tmp_path: Path) -> None:
    shards = [
        ["tests/test_a.py::test_a"],
        ["tests/test_b.py::test_b", "tests/test_b.py::test_c"],
    ]

    write_shard_plan(
        tmp_path,
        shards=shards,
        estimated_loads=[1.25, 2.5],
        manifest_used=True,
    )

    assert (tmp_path / "shard-00.txt").read_text(encoding="utf-8") == "tests/test_a.py::test_a\n"
    assert (tmp_path / "shard-01.txt").read_text(encoding="utf-8") == (
        "tests/test_b.py::test_b\ntests/test_b.py::test_c\n"
    )
    response_nodes = [
        node_id
        for response_file in sorted(tmp_path.glob("shard-*.txt"))
        for node_id in response_file.read_text(encoding="utf-8").splitlines()
    ]
    assert response_nodes == [node_id for shard in shards for node_id in shard]
    assert len(response_nodes) == len(set(response_nodes))
    assert json.loads((tmp_path / "plan.json").read_text(encoding="utf-8")) == {
        "schema_version": 1,
        "shard_count": 2,
        "node_count": 3,
        "duration_manifest_used": True,
        "estimated_load_seconds": [1.25, 2.5],
        "node_counts": [1, 2],
        "file_counts": [1, 1],
    }
