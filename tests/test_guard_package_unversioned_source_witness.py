"""Verify source attribution follows the actual bound evaluator callables."""

from __future__ import annotations

import hashlib
from importlib.util import module_from_spec, spec_from_file_location
from types import ModuleType

import pytest

from scripts.qualify_guard_package_unversioned_route import _bound_lookup_source_records


def _caller_facade(tmp_path, first_body, *, parameter=""):
    source = (
        f"def _evaluate_with_bundle({parameter}):\n"
        + "".join("    " + line + "\n" for line in first_body.splitlines())
        + "\ndef _transitive_lockfile_results():\n"
        + "    return evaluate_cached_supply_chain_bundle()\n"
    )
    path = tmp_path / "actual_callers.py"
    path.write_text(source)
    spec = spec_from_file_location("actual_witness_callers", path)
    assert spec is not None and spec.loader is not None
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    facade = ModuleType("witness_evaluator_facade")
    facade.evaluate_cached_supply_chain_bundle = lambda: None
    module.evaluate_cached_supply_chain_bundle = facade.evaluate_cached_supply_chain_bundle
    module._eval = facade
    facade._evaluate_with_bundle = module._evaluate_with_bundle
    facade._transitive_lockfile_results = module._transitive_lockfile_results
    return facade, module, path


@pytest.mark.parametrize(
    "expression", ["evaluate_cached_supply_chain_bundle()", "_eval.evaluate_cached_supply_chain_bundle()"]
)
def test_source_witness_uses_actual_callable_path_and_binding(tmp_path, expression):
    facade, _, path = _caller_facade(tmp_path, "return " + expression)

    records = _bound_lookup_source_records(tmp_path, facade)

    assert [record["facade_binding"] for record in records] == [
        "_evaluate_with_bundle",
        "_transitive_lockfile_results",
    ]
    assert all(record["source_path"] == "actual_callers.py" for record in records)
    assert all(record["source_sha256"] == hashlib.sha256(path.read_bytes()).hexdigest() for record in records)
    assert records[0]["lookup_calls"] == [{"line": 2, "column": 11, "expression": expression.removesuffix("()")}]


def test_source_witness_excludes_nested_and_comprehension_scopes(tmp_path):
    body = (
        "def nested(_eval):\n"
        "    return _eval.evaluate_cached_supply_chain_bundle()\n"
        "class Nested:\n"
        "    value = _eval.evaluate_cached_supply_chain_bundle()\n"
        "callback = lambda: _eval.evaluate_cached_supply_chain_bundle()\n"
        "values = [_eval.evaluate_cached_supply_chain_bundle() for _eval in ()]\n"
        "return _eval.evaluate_cached_supply_chain_bundle()"
    )
    facade, _, _ = _caller_facade(tmp_path, body)

    records = _bound_lookup_source_records(tmp_path, facade)

    assert records[0]["lookup_calls"] == [
        {"line": 8, "column": 11, "expression": "_eval.evaluate_cached_supply_chain_bundle"},
    ]


def test_source_witness_rejects_locally_shadowed_facade_alias(tmp_path):
    facade, _, _ = _caller_facade(
        tmp_path,
        "return _eval.evaluate_cached_supply_chain_bundle()",
        parameter="_eval",
    )

    with pytest.raises(AssertionError, match="No bound outer lookup call"):
        _bound_lookup_source_records(tmp_path, facade)


def test_source_witness_rejects_an_unrelated_global_lookup(tmp_path):
    facade, module, _ = _caller_facade(tmp_path, "return evaluate_cached_supply_chain_bundle()")
    module.evaluate_cached_supply_chain_bundle = lambda: "different lookup"

    with pytest.raises(AssertionError, match="No bound outer lookup call"):
        _bound_lookup_source_records(tmp_path, facade)
