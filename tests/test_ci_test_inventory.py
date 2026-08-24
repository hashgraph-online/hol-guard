from __future__ import annotations

import gzip
import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = ROOT / "scripts" / "ci" / "test_inventory.py"
SPEC = importlib.util.spec_from_file_location("test_inventory", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
test_inventory = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = test_inventory
SPEC.loader.exec_module(test_inventory)


def test_inventory_contract_helpers(tmp_path: Path) -> None:
    assert test_inventory.test_function_id("tests/test_example.py::test_case[value]") == (
        "tests/test_example.py::test_case"
    )
    assert test_inventory.test_function_id("tests/test_example.py::test_case") == "tests/test_example.py::test_case"
    node_ids = (
        "tests/test_alpha.py::test_one[first]",
        "tests/test_alpha.py::test_one[second]",
        "tests/test_beta.py::test_two",
    )
    inventory = test_inventory.build_inventory(
        node_ids,
        {
            node_ids[0]: ("security_critical", "regression", "regression"),
            node_ids[1]: ("security_critical",),
            node_ids[2]: ("parser",),
        },
    )

    assert inventory.collected_cases == 3
    assert inventory.test_functions == 2
    assert inventory.test_files == 2
    assert inventory.parameterized_cases == 1
    assert inventory.marker_counts == {"parser": 1, "regression": 1, "security_critical": 2}
    path = tmp_path / "durations.json.gz"
    path.write_bytes(
        gzip.compress(
            json.dumps(
                {
                    "observed_at": "2026-07-26T16:49:42Z",
                    "node_durations_seconds": {"hashed-node-a": 1.25, "hashed-node-b": 2.5},
                }
            ).encode("utf-8"),
            mtime=0,
        )
    )

    assert test_inventory.load_duration_summary(path) == test_inventory.DurationSummary(
        known_node_count=2,
        predicted_runtime_seconds=3.75,
        observed_at="2026-07-26T16:49:42Z",
    )
    path = tmp_path / "durations.json"
    path.write_text(
        json.dumps({"observed_at": "2026-07-26T16:49:42Z", "node_durations_seconds": {"node": "fast"}}),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="invalid duration"):
        test_inventory.load_duration_summary(path)
