"""Guard the recorded action-lattice decisions both Rust twins replay.

``rust/crates/guard-command/tests/guard_action_normalization_parity.rs`` and
``rust/crates/guard-contracts/tests/action_normalization_parity.rs`` read the
same fixture. The lattice decides which action wins when several parts of Guard
disagree, and three separate implementations answer that question: this module,
``guard-command``'s ``action_lattice`` and ``guard-contracts``'s
``decision_lattice``. A change to any of them that this file does not also
record is caught here first.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard.action_lattice import (
    guard_action_severity,
    is_action_bearing_key,
    most_restrictive_guard_action,
    normalize_guard_action_result,
)

FIXTURE = Path(__file__).resolve().parents[1] / "tests/fixtures/guard-action-normalization.v1.json"


def _document() -> dict[str, Any]:
    document = json.loads(FIXTURE.read_text(encoding="utf-8"))
    assert document["schema"] == "guard-action-normalization-parity.v1"
    return document


def _values() -> list[dict[str, Any]]:
    return _document()["values"]


def _compositions() -> list[dict[str, Any]]:
    return _document()["compositions"]


def _keys() -> list[dict[str, Any]]:
    return _document()["action_bearing_keys"]


@pytest.mark.parametrize("case", _values(), ids=lambda case: case["name"])
def test_recorded_normalization_still_holds(case: dict[str, Any]) -> None:
    value = json.loads(case["value_json"])
    normalized = normalize_guard_action_result(value)

    assert normalized.action == case["action"]
    assert normalized.reason_code == case["reason_code"]
    assert normalized.original_action == case["original_action"]
    # The diagnostic names the input's own Python type, so a reader can tell a
    # malformed action from a missing one without the value being echoed back.
    assert normalized.original_type == case["original_type"]
    assert normalized.recognized == case["recognized"]
    assert guard_action_severity(value) == case["severity"]


@pytest.mark.parametrize("case", _compositions(), ids=lambda case: case["name"])
def test_recorded_composition_still_holds(case: dict[str, Any]) -> None:
    values = [json.loads(item) for item in case["values_json"]]
    assert most_restrictive_guard_action(*values) == case["action"]


@pytest.mark.parametrize("case", _keys(), ids=lambda case: case["key"] or "empty")
def test_recorded_action_bearing_key_still_holds(case: dict[str, Any]) -> None:
    assert is_action_bearing_key(case["key"]) == case["action_bearing"]


def test_the_fixture_keeps_recording_every_action_in_the_lattice() -> None:
    recorded = {case["action"] for case in _values()}
    assert recorded == {
        "allow",
        "warn",
        "review",
        "require-reapproval",
        "sandbox-required",
        "block",
    }, sorted(recorded)


def test_the_fixture_keeps_recording_values_that_are_not_actions() -> None:
    unrecognized = [case["name"] for case in _values() if not case["recognized"]]
    assert len(unrecognized) >= 8, unrecognized


def test_the_fixture_keeps_recording_every_non_string_json_type() -> None:
    # Each one reaches a different branch of the Rust `Value` match, so dropping
    # a type here would let that branch drift unnoticed.
    recorded = {case["original_type"] for case in _values()}
    assert {"NoneType", "bool", "int", "float", "list", "dict", "str"} <= recorded, sorted(recorded)
