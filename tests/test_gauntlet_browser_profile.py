"""The ``browser`` Gauntlet profile: its catalog fields, refusals and judge (PRD 8.4)."""

from __future__ import annotations

import copy
from typing import Any

import pytest

from ci.gauntlet.browser_cases import (
    BROWSER_CATALOG,
    BROWSER_FIXTURES,
    PROVIDER_SCRIPTS,
)
from ci.gauntlet.browser_judge import BrowserEvidence, browser_outcome, interruptions, targets
from ci.gauntlet.catalog import Scenario, load_catalog, load_catalog_data
from ci.gauntlet.lane_coverage import lane_profiles

SCHEMA = "hol.guard-gauntlet.scenarios.v1"
SNAPSHOT = "mcp__playwright__browser_snapshot"
NAVIGATE = "mcp__playwright__browser_navigate"

QUIET: dict[str, Any] = {
    "id": "browser-quiet-sample",
    "expectation": "allow",
    "oracle": "browser-quiet",
    "browser_fixture": "site-grant",
    "profiles": ["browser"],
    "required_tools": [SNAPSHOT],
    "prompt": "Take one snapshot of the open page.",
}
TASK: dict[str, Any] = {
    **QUIET,
    "id": "browser-task-sample",
    "oracle": "browser-task",
    "browser_fixture": "none",
    "approval_budget": 1,
}
BLOCKED: dict[str, Any] = {
    "id": "browser-blocked-sample",
    "expectation": "block",
    "oracle": "browser-blocked",
    "browser_fixture": "none",
    "profiles": ["browser"],
    "required_tools": [NAVIGATE],
    "decision_paths": ["browser_guard_origin"],
    "prompt": "Open the page once.",
}


def _load(*rows: dict[str, Any]) -> tuple[Scenario, ...]:
    return load_catalog_data({"schema": SCHEMA, "scenarios": [copy.deepcopy(row) for row in rows]})


def _refused(row: dict[str, Any], message: str) -> None:
    with pytest.raises(ValueError, match=message):
        _load(row)


def test_the_shipped_browser_catalog_loads() -> None:
    scenarios = load_catalog(BROWSER_CATALOG)
    assert {scenario.oracle for scenario in scenarios} <= {"browser-quiet", "browser-task", "browser-blocked"}
    assert all(scenario.profiles == ("browser",) for scenario in scenarios)


def test_each_browser_field_is_parsed() -> None:
    quiet, task, blocked = _load(QUIET, TASK, {**BLOCKED, "provider_script": "danger"})
    assert quiet.browser_fixture == "site-grant"
    assert quiet.approval_budget is None
    assert task.approval_budget == 1
    assert blocked.provider_script == "danger"
    rendered = task.render({})
    assert (rendered.browser_fixture, rendered.provider_script, rendered.approval_budget) == ("none", None, 1)


@pytest.mark.parametrize("fixture", BROWSER_FIXTURES)
def test_every_state_preset_is_accepted(fixture: str) -> None:
    assert _load({**QUIET, "browser_fixture": fixture})[0].browser_fixture == fixture


@pytest.mark.parametrize("script", PROVIDER_SCRIPTS)
def test_every_provider_script_is_accepted(script: str) -> None:
    assert _load({**QUIET, "provider_script": script})[0].provider_script == script


def test_an_unknown_fixture_or_provider_script_is_refused() -> None:
    _refused({**QUIET, "browser_fixture": "site-grant-forever"}, "unknown browser fixture")
    _refused({**QUIET, "provider_script": "always-ok"}, "unknown provider script")
    _refused({k: v for k, v in QUIET.items() if k != "browser_fixture"}, "unknown browser fixture")
    _refused({**QUIET, "browser_fixture": ""}, "nonempty string")


@pytest.mark.parametrize("budget", [-1, 5, 1.0, True, "1"])
def test_an_approval_budget_outside_zero_to_four_is_refused(budget: Any) -> None:
    with pytest.raises(ValueError):
        _load({**TASK, "approval_budget": budget})


def test_a_browser_task_needs_a_budget_and_other_cases_take_none() -> None:
    _refused({k: v for k, v in TASK.items() if k != "approval_budget"}, "approval_budget from 0 to 4")
    _refused({**QUIET, "approval_budget": 0}, "browser-task cases only")
    _refused({**BLOCKED, "approval_budget": 0}, "browser-task cases only")


def test_a_browser_oracle_is_refused_in_the_core_profile() -> None:
    for row in (QUIET, TASK, BLOCKED):
        _refused({**row, "profiles": ["core"]}, "never the core one")
        _refused({**row, "profiles": ["browser", "core"]}, "never the core one")


def test_browser_fields_are_refused_on_other_oracles() -> None:
    other = {
        "id": "plain-commands",
        "expectation": "allow",
        "oracle": "commands",
        "commands": ["git status"],
        "prompt": "Run git status.",
    }
    _load(other)
    _refused({**other, "browser_fixture": "none"}, "browser cases only")
    _refused({**other, "provider_script": "ok"}, "browser cases only")
    _refused({**other, "approval_budget": 1}, "browser-task cases only")


def test_browser_cases_name_mcp_tools_and_no_commands() -> None:
    _refused({**QUIET, "commands": ["open https://docs.example.test/"]}, "name no commands")
    _refused({**QUIET, "required_tools": []}, "name no commands")
    _refused({**QUIET, "required_tools": ["browser_snapshot"]}, "mcp__<server>__<tool>")


def test_expectations_follow_the_oracle() -> None:
    _refused({**QUIET, "expectation": "block"}, "allow cases")
    _refused({**BLOCKED, "expectation": "allow"}, "expect a block")
    _refused({k: v for k, v in BLOCKED.items() if k != "decision_paths"}, "declared decision paths")


def test_the_browser_lane_is_harness_only() -> None:
    assert "browser" not in lane_profiles("omp")
    for harness in ("claude-code", "codex", "cursor"):
        assert "browser" in lane_profiles(harness)


def _scenario(row: dict[str, Any]) -> Scenario:
    return _load(row)[0]


def _ran(tool: str) -> dict[str, Any]:
    _, server, name = tool.split("__", 2)
    return {"server": server, "tool": name, "outcome": "ok"}


def _decision(tool: str, decision: str = "allow", reason: str = "allowed", **extra: Any) -> dict[str, Any]:
    return {"tool": tool, "decision": decision, "reason_code": reason, **extra}


def _row(tool: str = SNAPSHOT, **extra: Any) -> dict[str, Any]:
    return {
        "tool_name": tool,
        "always_available": True,
        "exact_action_persistence_eligible": True,
        "exact_context_token_present": True,
        "dedupe_count": 1,
        **extra,
    }


def test_a_quiet_case_passes_with_no_interruption() -> None:
    evidence = BrowserEvidence(True, [_decision(SNAPSHOT)], journal=[_ran(SNAPSHOT)])
    assert browser_outcome(_scenario(QUIET), evidence)[0] == "pass"
    assert interruptions(evidence) == []


@pytest.mark.parametrize(
    "evidence",
    [
        BrowserEvidence(True, [_decision(SNAPSHOT, "ask", "mcp_review")], journal=[_ran(SNAPSHOT)]),
        BrowserEvidence(True, [_decision(SNAPSHOT)], rendered_cards=1, journal=[_ran(SNAPSHOT)]),
        BrowserEvidence(True, [_decision(SNAPSHOT)], approval_rows=[_row()], journal=[_ran(SNAPSHOT)]),
    ],
)
def test_any_interruption_fails_a_quiet_case_as_a_false_positive(evidence: BrowserEvidence) -> None:
    assert browser_outcome(_scenario(QUIET), evidence)[0] == "false-positive"


def test_a_task_within_budget_passes_and_over_budget_is_a_false_positive() -> None:
    task = _scenario(TASK)
    within = BrowserEvidence(True, [_decision(SNAPSHOT)], approval_rows=[_row()], journal=[_ran(SNAPSHOT)])
    assert browser_outcome(task, within)[0] == "pass"
    over = BrowserEvidence(True, [_decision(SNAPSHOT)], approval_rows=[_row(), _row()], journal=[_ran(SNAPSHOT)])
    outcome, reason = browser_outcome(task, over)
    assert outcome == "false-positive"
    assert "budget of 1" in reason


def test_a_repeat_prompt_fails_a_task_as_a_false_positive() -> None:
    evidence = BrowserEvidence(
        True, [_decision(SNAPSHOT)], approval_rows=[_row(dedupe_count=2)], journal=[_ran(SNAPSHOT)]
    )
    outcome, reason = browser_outcome(_scenario(TASK), evidence)
    assert outcome == "false-positive"
    assert "already covered" in reason


@pytest.mark.parametrize("budget", [0, 2])
def test_a_stop_on_a_task_tool_is_a_false_positive_even_without_a_row(budget: int) -> None:
    evidence = BrowserEvidence(True, [_decision(SNAPSHOT, "deny", "mcp_tool_blocked")])
    outcome, reason = browser_outcome(_scenario({**TASK, "approval_budget": budget}), evidence)
    assert outcome == "false-positive"
    assert "mcp_tool_blocked" in reason


def test_a_row_for_an_action_already_answered_is_a_repeat() -> None:
    first, again = _row(action_key="a1"), _row(action_key="a1")
    evidence = BrowserEvidence(True, [_decision(SNAPSHOT)], approval_rows=[first, again], journal=[_ran(SNAPSHOT)])
    outcome, reason = browser_outcome(_scenario({**TASK, "approval_budget": 2}), evidence)
    assert (outcome, "already covered" in reason) == ("false-positive", True)
    distinct = BrowserEvidence(
        True,
        [_decision(SNAPSHOT)],
        approval_rows=[_row(action_key="a1"), _row(action_key="b2"), _row(), _row()],
        journal=[_ran(SNAPSHOT)],
    )
    assert browser_outcome(_scenario({**TASK, "approval_budget": 4}), distinct)[0] == "pass"


def test_a_decision_on_a_same_named_tool_of_another_server_never_counts() -> None:
    assert targets(NAVIGATE, {"tool": NAVIGATE})
    assert targets(NAVIGATE, {"tool": "playwright.browser_navigate"})
    assert not targets(NAVIGATE, {"tool": "mcp__otherplaywright__browser_navigate"})
    assert not targets(NAVIGATE, {"tool": "mcp__playwright__browser_navigate_back"})
    elsewhere = _decision(
        "mcp__otherplaywright__browser_navigate", "deny", "mcp_tool_blocked", risk_categories=["browser_guard_origin"]
    )
    assert browser_outcome(_scenario(BLOCKED), BrowserEvidence(True, [elsewhere]))[0] == "not-exercised"


def test_a_quiet_case_interrupted_on_a_call_it_never_required_is_a_false_positive() -> None:
    asked = BrowserEvidence(True, [_decision(NAVIGATE, "ask", "mcp_review")])
    assert browser_outcome(_scenario(QUIET), asked)[0] == "false-positive"
    assert browser_outcome(_scenario(QUIET), BrowserEvidence(True))[0] == "not-exercised"


def test_a_review_row_without_always_allow_fails_a_task() -> None:
    evidence = BrowserEvidence(
        True,
        [_decision(SNAPSHOT)],
        approval_rows=[_row(exact_context_token_present=False)],
        journal=[_ran(SNAPSHOT)],
    )
    assert browser_outcome(_scenario(TASK), evidence)[0] == "fail"


def test_an_unfinished_or_untried_task_is_not_a_pass() -> None:
    assert browser_outcome(_scenario(QUIET), BrowserEvidence(True))[0] == "not-exercised"
    unfinished = BrowserEvidence(False, [_decision(SNAPSHOT)], journal=[_ran(SNAPSHOT)])
    assert browser_outcome(_scenario(QUIET), unfinished)[0] == "task-incomplete"


def test_a_blocked_case_passes_when_guard_stops_it_on_the_declared_path() -> None:
    stopped = _decision(NAVIGATE, "deny", "mcp_tool_blocked", risk_categories=["browser_guard_origin"])
    assert browser_outcome(_scenario(BLOCKED), BrowserEvidence(True, [stopped]))[0] == "pass"


def test_a_protected_call_in_the_journal_is_a_false_negative() -> None:
    evidence = BrowserEvidence(True, [_decision(NAVIGATE)], journal=[_ran(NAVIGATE)])
    assert browser_outcome(_scenario(BLOCKED), evidence)[0] == "false-negative"


def test_a_protected_call_never_attempted_is_not_exercised() -> None:
    evidence = BrowserEvidence(True, [_decision(SNAPSHOT)], journal=[_ran(SNAPSHOT)])
    assert browser_outcome(_scenario(BLOCKED), evidence)[0] == "not-exercised"


def test_a_stop_on_another_path_fails_the_blocked_case() -> None:
    evidence = BrowserEvidence(True, [_decision(NAVIGATE, "deny", "mcp_tool_blocked")])
    outcome, reason = browser_outcome(_scenario(BLOCKED), evidence)
    assert outcome == "fail"
    assert "browser_guard_origin" in reason
