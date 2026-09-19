from __future__ import annotations

import copy

import pytest

from scripts.native_slo_workspace_scopes import scope_checks


def _compile(count, scopes, *, publication=1):
    return {
        "kind": "compile",
        "publication": publication,
        "succeeded": True,
        "registered_workspaces": count,
        "cache_entries": count + 1,
        "scope_loads": scopes,
        "config_loads": sum(scopes),
        "unregistered_loads": 0,
        "config_load_failures": 0,
        "scope_counts_overflow": False,
    }


@pytest.mark.parametrize("count", [1, 10, 100])
def test_initial_requires_every_real_scope_once_and_complete_acknowledged_cache(count):
    row = _compile(count, [1] * (count + 1))
    assert all(scope_checks("initial", count, [row], {"matched": True, "publication": 1}).values())
    missing = copy.deepcopy(row)
    missing["scope_loads"][-1] = 0
    missing["config_loads"] -= 1
    checks = scope_checks("initial", count, [missing], {"matched": True, "publication": 1})
    assert checks["compile_load_counts_reconcile"] and not checks["all_scopes_loaded_once"]


@pytest.mark.parametrize(
    "field,value",
    [
        ("cache_entries", 1),
        ("registered_workspaces", 1),
        ("unregistered_loads", 1),
        ("config_load_failures", 1),
        ("scope_counts_overflow", True),
        ("config_loads", 100),
        ("scope_loads", [1] * 100),
        ("scope_loads", [True] * 101),
    ],
)
def test_scope_and_cache_failures_cannot_pass_installed_feature_gate(field, value):
    row = _compile(100, [1] * 101)
    row[field] = value
    assert not all(scope_checks("initial", 100, [row], {"matched": True, "publication": 1}).values())


@pytest.mark.parametrize("count", [1, 10, 100])
def test_burst_requires_every_changed_scope_even_when_all_native_probes_use_workspace_zero(count):
    scopes = [0] + [1 if index < 32 else 0 for index in range(count)]
    row = _compile(count, scopes)
    assert all(scope_checks("coalesced_burst", count, [row], {"matched": True, "publication": 1}).values())
    row["scope_loads"][-1 if count < 32 else 32] = 0
    row["config_loads"] -= 1
    assert not scope_checks("coalesced_burst", count, [row], {"matched": True, "publication": 1})[
        "all_changed_scopes_captured"
    ]


def test_uncached_compilation_is_recorded_as_feature_failure():
    row = _compile(100, [1] * 101)
    row["cache_entries"] = None
    checks = scope_checks("unchanged", 100, [row], {"matched": True, "publication": 1})
    assert checks["registered_scopes_complete"] and checks["compile_load_counts_reconcile"]
    assert not checks["unchanged_scopes_reused"] and not checks["compiled_cache_complete"]


def test_cache_entries_must_belong_to_the_acknowledged_publication():
    old = _compile(100, [1] * 101, publication=1)
    new = _compile(100, [0] * 101, publication=2)
    new["cache_entries"] = 1
    assert not scope_checks("initial", 100, [old, new], {"matched": True, "publication": 2})["compiled_cache_complete"]
