"""The whole tool response travels to the resident only when it can be reviewed there."""

from __future__ import annotations

import math

from codex_plugin_scanner.guard.cli.commands_support_runtime_artifacts import (
    _CODEX_POST_TOOL_REQUEST_BUDGET,
    _CODEX_TOOL_RESPONSE_MAX_NESTING,
    _codex_tool_response_within_budget,
)


def _body(response_text: str = "") -> dict[str, object]:
    return {
        "harness_label": "Codex",
        "tool_label": "Bash",
        "tool_name": "Bash",
        "tool_input": {"command": "ls"},
        "arguments": None,
        "tool_input_present": True,
        "response_text": response_text,
        "cwd": None,
        "home_dir": None,
        "deadline_ms": 8_000,
    }


def test_a_small_response_travels_whole() -> None:
    response = {"output": "token=abc"}
    assert _codex_tool_response_within_budget(_body("token=abc"), response) is response


def test_an_absent_response_sends_nothing() -> None:
    assert _codex_tool_response_within_budget(_body(), None) is None


def test_a_response_over_the_budget_is_left_behind() -> None:
    response = {"output": "x" * (_CODEX_POST_TOOL_REQUEST_BUDGET + 1)}
    assert _codex_tool_response_within_budget(_body(), response) is None


def test_the_rest_of_the_request_counts_against_the_budget() -> None:
    half = "x" * (_CODEX_POST_TOOL_REQUEST_BUDGET // 2)
    response = {"output": half}
    assert _codex_tool_response_within_budget(_body(), response) is response
    assert _codex_tool_response_within_budget(_body(half), response) is None


def test_a_large_tool_input_counts_against_the_budget() -> None:
    half = "x" * (_CODEX_POST_TOOL_REQUEST_BUDGET // 2)
    body = _body()
    body["tool_input"] = {"command": half}
    assert _codex_tool_response_within_budget(body, {"output": half}) is None


def test_a_response_that_will_not_serialize_is_left_behind() -> None:
    assert _codex_tool_response_within_budget(_body(), {"output": object()}) is None


def test_a_lone_surrogate_is_left_behind() -> None:
    assert _codex_tool_response_within_budget(_body(), {"metadata": "\ud800"}) is None


def test_a_non_finite_number_is_left_behind() -> None:
    assert _codex_tool_response_within_budget(_body(), {"metadata": math.nan}) is None
    assert _codex_tool_response_within_budget(_body(), {"metadata": math.inf}) is None


def test_a_response_nested_past_the_decoder_is_left_behind() -> None:
    nested: object = "token=abc"
    for _ in range(_CODEX_TOOL_RESPONSE_MAX_NESTING + 2):
        nested = {"inner": nested}
    assert _codex_tool_response_within_budget(_body(), nested) is None

    shallow: object = "token=abc"
    for _ in range(4):
        shallow = {"inner": shallow}
    assert _codex_tool_response_within_budget(_body(), shallow) is shallow
