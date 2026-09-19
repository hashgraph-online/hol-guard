"""Canonical row ordering retains expression and nested source authority."""

from __future__ import annotations

import copy
import json

import pytest

from codex_plugin_scanner.guard.native_policy_row_sort import native_policy_row_sort_key


def test_exact_utf8_sort_bytes_and_only_top_level_non_authority_fields():
    row = {
        "owner": "display owner",
        "decision_id": 73,
        "reason": "display reason",
        "artifact_id": "é😀",
        "action": "block",
        "_policy_rule_identity": {"ruleId": "rule-one", "owner": "retained nested field"},
    }
    before = copy.deepcopy(row)
    assert native_policy_row_sort_key(row) == (
        '{"_policy_rule_identity":{"owner":"retained nested field","ruleId":"rule-one"},'
        '"action":"block","artifact_id":"é😀"}'
    )
    assert row == before
    assert native_policy_row_sort_key({**row, "owner": "changed", "reason": "changed", "decision_id": 2}) == (
        native_policy_row_sort_key(row)
    )


def test_expression_and_provenance_changes_remain_in_sort_and_assignment_input():
    row = {
        "action": "block",
        "_command_expression_json": '{"value":"printf a"}',
        "_policy_rule_identity": {"ruleId": "a"},
    }
    expression_change = {**row, "_command_expression_json": '{"value":"printf b"}'}
    provenance_change = {**row, "_policy_rule_identity": {"ruleId": "b"}}
    assert len({native_policy_row_sort_key(item) for item in (row, expression_change, provenance_change)}) == 3
    assert json.loads(native_policy_row_sort_key(row)) == row


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
def test_non_finite_source_values_are_not_canonical(value):
    with pytest.raises(ValueError):
        native_policy_row_sort_key({"action": "block", "unexpected": value})
