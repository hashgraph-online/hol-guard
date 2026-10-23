"""The macOS matrix must partition the full native gate, not skip slow cases."""

import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("node_count", [137, 9797])
def test_macos_gates_require_every_disjoint_shard(node_count):
    workflow = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())
    job = workflow["jobs"]["macos-gates"]
    indices = job["strategy"]["matrix"]["shard-index"]
    assert indices == list(range(12))
    assert job["strategy"]["fail-fast"] is False
    assert job["timeout-minutes"] == 5
    assert "macos-gates" in workflow["jobs"]["required"]["needs"]
    action = next(step for step in job["steps"] if step.get("uses", "").endswith("ci-job-macos-skill-identity"))
    assert action["with"]["shard-index"] == "${{ matrix.shard-index }}"
    assert action["with"]["shard-count"] == len(indices)

    definition = yaml.safe_load((ROOT / ".github/actions/ci-job-macos-skill-identity/action.yml").read_text())
    step = next(item for item in definition["runs"]["steps"] if item.get("env", {}).get("SHARD_INDEX"))
    command = step["run"]
    assert all(
        name in command
        for name in (
            "test_guard_benign_false_positive_gate.py",
            "test_guard_gauntlet_replay_gate.py",
            "test_guard_command_corpus_benign_allow.py",
        )
    )
    assert "set -o pipefail" in command
    assert "test -s gate-shard.txt" in command
    assert "--max-worker-restart 0" in command
    assert "-n 3" in command
    assert "--durations=10" in command
    partition = next(line for line in command.splitlines() if "| awk " in line)
    expression = partition.split("'", 2)[1]
    nodes = [f"tests/test_gate.py::case_{index:05}" for index in range(node_count)]
    selected = []
    for index in indices:
        result = subprocess.run(
            ["awk", "-v", f"n={len(indices)}", "-v", f"i={index}", expression],
            input="\n".join(nodes) + "\n",
            text=True,
            check=True,
            capture_output=True,
        )
        shard = result.stdout.splitlines()
        assert shard
        previous = []
        for old_index in (index, index + len(indices)):
            control = subprocess.run(
                ["awk", "-v", f"n={len(indices) * 2}", "-v", f"i={old_index}", expression],
                input="\n".join(nodes) + "\n",
                text=True,
                check=True,
                capture_output=True,
            )
            previous.extend(control.stdout.splitlines())
        assert sorted(shard) == sorted(previous)
        selected.extend(shard)
    assert len(selected) == len(set(selected)) == len(nodes)
    assert sorted(selected) == nodes
