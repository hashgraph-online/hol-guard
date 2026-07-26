from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = ROOT / "scripts" / "ci" / "test_inventory.py"
SPEC = importlib.util.spec_from_file_location("test_inventory", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
test_inventory = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = test_inventory
SPEC.loader.exec_module(test_inventory)


def test_function_id_removes_parameter_suffix_only() -> None:
    assert test_inventory.test_function_id("tests/test_example.py::test_case[value]") == (
        "tests/test_example.py::test_case"
    )
    assert test_inventory.test_function_id("tests/test_example.py::test_case") == "tests/test_example.py::test_case"


def test_inventory_counts_cases_functions_files_parameters_and_unique_markers() -> None:
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
