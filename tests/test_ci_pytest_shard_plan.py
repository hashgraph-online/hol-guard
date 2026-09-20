from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.ci.build_pytest_shard_plan import (
    SCHEDULING_ONLY_NODE_IDS,
    _split_file_nodes,
    build_affinity_node_shards,
    estimate_node_durations,
    node_file,
    write_shard_plan,
)
from scripts.ci.pytest_duration_manifest import node_id_digest


def _durations(nodes: list[str], *, seconds: float = 1.0) -> dict[str, float]:
    return {node_id_digest(node_id): seconds for node_id in nodes}


def test_new_parameters_inherit_unsplit_duration_without_overriding_observations() -> None:
    parent = "tests/test_corpus.py::test_all_cases"
    nodes = [f"{parent}[{index}]" for index in range(4)]
    durations = {node_id_digest(parent): 320.0, node_id_digest(nodes[0]): 90.0}

    assert estimate_node_durations(nodes, durations) == {
        nodes[0]: 90.0,
        nodes[1]: 80.0,
        nodes[2]: 80.0,
        nodes[3]: 80.0,
    }


def test_parameterized_long_corpus_is_distributed_on_first_run() -> None:
    parent = "tests/test_corpus.py::test_all_cases"
    corpus = [f"{parent}[{index}]" for index in range(32)]
    filler = [f"tests/test_filler_{index}.py::test_one" for index in range(32)]
    durations = {node_id_digest(parent): 320.0}

    shards, loads = build_affinity_node_shards(corpus + filler, 8, durations)

    assert max(loads) <= 50.0
    assert sum(any(node in corpus for node in shard) for shard in shards) == 8
    assert sorted(node for shard in shards for node in shard) == sorted(corpus + filler)


def test_affinity_plan_covers_every_node_once_and_is_deterministic() -> None:
    nodes = [f"tests/test_{file_index}.py::test_{test_index}" for file_index in range(8) for test_index in range(8)]
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


def test_scheduling_only_nodes_cannot_own_or_inflate_a_coverage_shard() -> None:
    scheduling_nodes = sorted(SCHEDULING_ONLY_NODE_IDS)
    # A similarly named test in the same file still belongs in coverage.
    traced_nodes = [f"{node}_followup" for node in scheduling_nodes]
    durations = {**_durations(scheduling_nodes, seconds=600.0), **_durations(traced_nodes)}

    shards, loads = build_affinity_node_shards(scheduling_nodes + traced_nodes, len(traced_nodes), durations)

    assert all(shards)
    assert sorted(node for shard in shards for node in shard) == sorted(traced_nodes)
    assert loads == [1.0] * len(traced_nodes)
    assert not SCHEDULING_ONLY_NODE_IDS.intersection(node for shard in shards for node in shard)


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


def test_file_packing_adds_bins_when_total_duration_lower_bound_is_insufficient() -> None:
    file_path = "tests/test_reports.py"
    estimates = {
        f"{file_path}::test_report[utc]": 47.0,
        f"{file_path}::test_report[pacific]": 47.0,
        f"{file_path}::test_source_binding": 41.0,
    }

    groups = _split_file_nodes(file_path, list(estimates), estimates, target_seconds=75.0)

    assert len(groups) == 3
    assert sorted(node for _path, _index, nodes, _load in groups for node in nodes) == sorted(estimates)
    assert all(load <= 75.0 for _path, _index, _nodes, load in groups)


def test_file_packing_allows_only_individually_oversized_nodes_to_exceed_target() -> None:
    file_path = "tests/test_soak.py"
    estimates = {f"{file_path}::test_soak": 100.0}
    estimates.update({f"{file_path}::test_small_{index}": 10.0 for index in range(4)})

    groups = _split_file_nodes(file_path, list(estimates), estimates, target_seconds=50.0)

    assert sorted(node for _path, _index, nodes, _load in groups for node in nodes) == sorted(estimates)
    assert all(load <= 50.0 or len(nodes) == 1 for _path, _index, nodes, load in groups)


def test_file_packing_preserves_existing_small_whole_file_allowance() -> None:
    file_path = "tests/test_small.py"
    estimates = {f"{file_path}::test_{index}": 40.0 for index in range(2)}

    groups = _split_file_nodes(file_path, list(estimates), estimates, target_seconds=75.0)

    assert len(groups) == 1
    assert groups[0][2] == sorted(estimates)
    assert groups[0][3] == 80.0


def test_affinity_plan_caps_large_files_without_duration_telemetry() -> None:
    large = [f"tests/test_slow.py::test_{index}" for index in range(148)]
    filler = [f"tests/test_filler_{index}.py::test_one" for index in range(148)]

    shards, _loads = build_affinity_node_shards(large + filler, 8, {})

    large_nodes_per_shard = [sum(node_file(node_id) == "tests/test_slow.py" for node_id in shard) for shard in shards]
    assert max(large_nodes_per_shard) <= 32
    assert sum(count > 0 for count in large_nodes_per_shard) == 5


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


def test_large_matrix_response_names_match_three_digit_workflow_format(tmp_path: Path) -> None:
    shards = [[f"tests/test_matrix.py::test_case_{index}"] for index in range(192)]

    write_shard_plan(tmp_path, shards=shards, estimated_loads=[1.0] * 192, manifest_used=True)

    assert len(list(tmp_path.glob("shard-*.txt"))) == 192
    assert [
        (tmp_path / f"shard-{index:03d}.txt").read_text(encoding="utf-8").splitlines() for index in range(192)
    ] == shards
