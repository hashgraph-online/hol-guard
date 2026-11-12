"""The Oh My Pi judge accepts the extension's prompt review as Guard evidence.

The Pi and Oh My Pi extension asks Guard about each prompt before its turn
starts. That answer names no tool, so it binds to no call, but the native
routes count it. The judge has to set an allowed prompt answer aside and still
count it, rather than fail every case as a malformed observation.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

import pytest

from ci.gauntlet.evidence import assess_case
from ci.gauntlet.input_evidence import input_digest, public_observations
from ci.gauntlet.proofs import guard_inventory
from tests.test_guard_gauntlet import observed_case, ordinary


def _prompt_answer(decision: str = "allow", **extra: Any) -> dict[str, Any]:
    return {
        "event": "UserPromptSubmit",
        "input": {},
        "input_sha256": input_digest({}),
        "observed_input_sha256": hashlib.sha256(b"{}").hexdigest(),
        "rendered_fields": [],
        "decision": decision,
        "http_status": 200,
        "reason_code": "native_prompt_allowed",
        **extra,
    }


def _with_prompt(prompt: dict[str, Any], routes: int = 3) -> dict[str, Any]:
    case = observed_case()
    case["guard_observations"].insert(0, prompt)
    case["native_routes"] = {"native_resident": routes}
    return case


def _calls() -> list[dict[str, Any]]:
    return [{"id": "c1", "name": "bash", "args": {"command": "echo fixture"}, "is_error": False}]


def test_an_allowed_prompt_answer_counts_toward_the_routes_and_binds_to_no_call() -> None:
    case = _with_prompt(_prompt_answer())
    assert guard_inventory(_calls(), case["guard_observations"], case["native_routes"])[1] is None
    assert assess_case(ordinary(), case)["outcome"] == "pass"


def test_the_routes_must_still_account_for_the_prompt_answer() -> None:
    case = _with_prompt(_prompt_answer(), routes=2)
    error = guard_inventory(_calls(), case["guard_observations"], case["native_routes"])[1]
    assert error == "native route counts do not reconcile with observed Guard responses"


def test_a_held_prompt_fails_the_case() -> None:
    case = _with_prompt(_prompt_answer("deny"))
    error = guard_inventory(_calls(), case["guard_observations"], case["native_routes"])[1]
    assert error == "Guard did not let the case prompt run"


@pytest.mark.parametrize(
    "change",
    [
        {"http_status": 500},
        {"observer_error": True},
        {"tool_call_id": "c1"},
        {"tool": "bash"},
        {"input": {"prompt": "echo fixture"}},
        {"input_sha256": "0" * 64},
    ],
)
def test_a_prompt_answer_that_is_not_a_clean_allow_is_malformed(change: dict[str, Any]) -> None:
    case = _with_prompt(_prompt_answer(**change))
    error = guard_inventory(_calls(), case["guard_observations"], case["native_routes"])[1]
    assert error == "malformed or unsuccessful Guard HTTP observation"


def test_the_observer_records_a_prompt_answer_as_an_empty_input_the_judge_accepts() -> None:
    row = {
        "event": "UserPromptSubmit",
        "input_json": "{}",
        "input_sha256": hashlib.sha256(b"{}").hexdigest(),
        "http_status": 200,
        "decision": "allow",
        "reason_code": "native_prompt_allowed",
        "rendered_fields": [],
    }
    [public] = public_observations([row], {})
    assert public["input"] == {}
    assert public["input_sha256"] == input_digest({})
    case = _with_prompt(public)
    assert guard_inventory(_calls(), case["guard_observations"], case["native_routes"])[1] is None


def test_a_prompt_answer_without_an_object_input_stays_an_observer_error() -> None:
    raw = json.dumps(None)
    row = {
        "event": "UserPromptSubmit",
        "input_json": raw,
        "input_sha256": hashlib.sha256(raw.encode()).hexdigest(),
        "http_status": 200,
        "decision": "allow",
    }
    [public] = public_observations([row], {})
    assert public["observer_error_code"] == "input_not_object"
    case = _with_prompt(public)
    error = guard_inventory(_calls(), case["guard_observations"], case["native_routes"])[1]
    assert error == "malformed or unsuccessful Guard HTTP observation"
