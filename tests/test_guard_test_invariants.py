from __future__ import annotations

import ast
from pathlib import Path

from tests.guard_test_invariants import TEST_INVARIANTS, invariant_markers_for_nodeid

ROOT = Path(__file__).resolve().parents[1]


def _test_names(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    return {
        node.name
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith("test_")
    }


def test_invariant_ids_and_selectors_are_unique() -> None:
    assert len({invariant.invariant_id for invariant in TEST_INVARIANTS}) == len(TEST_INVARIANTS)
    assert len({invariant.selector for invariant in TEST_INVARIANTS}) == len(TEST_INVARIANTS)


def test_each_invariant_points_to_a_concrete_test_function() -> None:
    for invariant in TEST_INVARIANTS:
        path_value, separator, test_name = invariant.selector.partition("::")
        assert separator == "::"
        path = ROOT / path_value
        assert path.is_file(), invariant.invariant_id
        assert test_name in _test_names(path), invariant.invariant_id


def test_protected_invariants_include_required_security_markers() -> None:
    for invariant in TEST_INVARIANTS:
        markers = invariant_markers_for_nodeid(invariant.selector)
        assert "security_critical" in markers, invariant.invariant_id
        assert "regression" in markers, invariant.invariant_id
        assert "release" in markers, invariant.invariant_id


def test_unknown_node_has_no_invariant_markers() -> None:
    assert invariant_markers_for_nodeid("tests/test_unknown.py::test_unknown") == ()


def test_parameterized_case_inherits_base_invariant_markers() -> None:
    selector = (
        "tests/test_guard_package_shims.py::"
        "test_guard_protect_requires_reapproval_for_untrusted_package_sources_without_cloud"
    )
    assert invariant_markers_for_nodeid(f"{selector}[npm]") == invariant_markers_for_nodeid(selector)
