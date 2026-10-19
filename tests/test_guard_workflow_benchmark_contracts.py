"""Negative public-contract tests pin strict data-only parsing."""

import json

import pytest

from ci.gauntlet.benchmark.contracts import (
    ContractError,
    canonical_json,
    digest,
    load_record,
    validate_record,
)


def authorization():
    return {
        "schema_version": "1.0",
        "actor": "user",
        "tenant": "fixture",
        "accounts": ["account"],
        "resources": ["resource"],
        "data_projection": ["name"],
        "destinations": ["private"],
        "allowed_operations": ["read", "create-draft"],
        "terminal_effects": ["draft"],
        "write_budget": 2,
        "approval_policy": "draft-only",
        "policy_version": "v1",
    }


def test_validation_detaches_and_preserves_data():
    original = authorization()
    validated = validate_record("authorization", original)
    validated["resources"].append("other")
    assert original["resources"] == ["resource"]
    assert load_record("authorization", json.dumps(original)) == original
    assert digest(original) == digest(dict(reversed(list(original.items()))))


@pytest.mark.parametrize(
    "field,value",
    [
        ("write_budget", True),
        ("write_budget", 2.0),
        ("write_budget", "2"),
        ("accounts", "account"),
        ("schema_version", "0.9"),
        ("actor", None),
    ],
)
def test_mistyped_or_incompatible_records_fail(field, value):
    record = authorization()
    record[field] = value
    with pytest.raises(ContractError):
        validate_record("authorization", record)


@pytest.mark.parametrize("field", ["plugin", "python_module", "evaluator", "unexpected"])
def test_unknown_executable_and_ordinary_fields_fail(field):
    record = authorization()
    record[field] = "candidate.arbitrary_code"
    with pytest.raises(ContractError):
        validate_record("authorization", record)


def test_nonfinite_duplicate_and_nonjson_data_fail():
    for value in [float("nan"), float("inf"), float("-inf"), object(), ("tuple",)]:
        with pytest.raises(ContractError):
            canonical_json({"value": value})
    with pytest.raises(ContractError, match="duplicate"):
        load_record("authorization", '{"actor":"a","actor":"b"}')
    with pytest.raises(ContractError, match="non-finite"):
        load_record("authorization", '{"write_budget":NaN}')


def test_deep_and_oversized_records_fail_before_schema_walk():
    nested = {}
    for _ in range(40):
        nested = {"next": nested}
    with pytest.raises(ContractError, match="depth"):
        canonical_json(nested)
    with pytest.raises(ContractError, match="byte limit"):
        canonical_json("x" * (17 * 1024 * 1024))


def test_missing_and_nested_unknown_fields_fail():
    record = authorization()
    del record["tenant"]
    with pytest.raises(ContractError):
        validate_record("authorization", record)
    with pytest.raises(ContractError, match="unknown contract"):
        validate_record("module:execute", {})
