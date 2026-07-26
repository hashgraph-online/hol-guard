from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = ROOT / "scripts" / "ci" / "test_duplicate_candidates.py"
SPEC = importlib.util.spec_from_file_location("test_duplicate_candidates", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
duplicate_candidates = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = duplicate_candidates
SPEC.loader.exec_module(duplicate_candidates)


def test_duplicate_candidates_group_exact_bodies_but_not_different_assertions(tmp_path: Path) -> None:
    tests = tmp_path / "tests"
    tests.mkdir()
    first = tests / "test_first.py"
    first.write_text(
        "def test_one():\n    assert value == 1\n\ndef test_two():\n    assert value == 1\n",
        encoding="utf-8",
    )
    second = tests / "test_second.py"
    second.write_text("def test_three():\n    assert value == 2\n", encoding="utf-8")

    candidates = duplicate_candidates.duplicate_candidates((first, second), root=tmp_path)

    assert len(candidates) == 1
    assert candidates[0].node_ids == ("tests/test_first.py::test_one", "tests/test_first.py::test_two")


def test_duplicate_candidates_keep_parameterized_matrices_distinct(tmp_path: Path) -> None:
    tests = tmp_path / "tests"
    tests.mkdir()
    path = tests / "test_matrix.py"
    path.write_text(
        "import pytest\n\n"
        "@pytest.mark.parametrize('value', [1])\n"
        "def test_one(value):\n    assert value\n\n"
        "@pytest.mark.parametrize('value', [2])\n"
        "def test_two(value):\n    assert value\n",
        encoding="utf-8",
    )

    assert duplicate_candidates.duplicate_candidates((path,), root=tmp_path) == ()


def test_duplicate_candidates_include_test_methods_with_class_context(tmp_path: Path) -> None:
    tests = tmp_path / "tests"
    tests.mkdir()
    path = tests / "test_methods.py"
    path.write_text(
        "class First:\n    def test_one(self):\n        assert True\n\n"
        "class Second:\n    def test_two(self):\n        assert True\n",
        encoding="utf-8",
    )

    candidates = duplicate_candidates.duplicate_candidates((path,), root=tmp_path)

    assert candidates[0].node_ids == (
        "tests/test_methods.py::First::test_one",
        "tests/test_methods.py::Second::test_two",
    )


def test_duplicate_candidates_discover_nested_test_files(tmp_path: Path) -> None:
    tests = tmp_path / "tests"
    nested = tests / "adapter"
    nested.mkdir(parents=True)
    (tests / "test_root.py").write_text("def test_one():\n    assert True\n", encoding="utf-8")
    (nested / "test_nested.py").write_text("def test_two():\n    assert True\n", encoding="utf-8")

    candidates = duplicate_candidates.duplicate_candidates(tests.rglob("test_*.py"), root=tmp_path)

    assert candidates[0].node_ids == (
        "tests/adapter/test_nested.py::test_two",
        "tests/test_root.py::test_one",
    )
