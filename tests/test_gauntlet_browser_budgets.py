"""Browser release budgets (PRD 8.5) over synthetic case results; no live agent runs here."""

from __future__ import annotations

from typing import Any

import pytest

from ci.gauntlet.browser_budgets import BROWSER_BUDGET_NAMES, browser_budget_lines, browser_budgets
from ci.gauntlet.latency import summarize_hook_latency
from ci.gauntlet.release_budgets import budget_lines, release_budgets


def _case(case_id: str, oracle: str, *, outcome: str = "pass", benign: bool = True, **browser: Any) -> dict:
    return {
        "id": case_id,
        "outcome": outcome,
        "interruptions": {"benign": benign, "events": []},
        "browser": {"oracle": oracle, "driver_id": "playwright-mcp", **browser},
    }


def _quiet(case_id: str = "browser-quiet-a", **browser: Any) -> dict:
    return _case(case_id, "browser-quiet", **{"interruptions": 0, "completed": True, **browser})


def _task(case_id: str = "browser-task-a", rows: int = 1, budget: int = 1, **browser: Any) -> dict:
    return _case(case_id, "browser-task", approval_rows=rows, approval_budget=budget, completed=True, **browser)


def _blocked(case_id: str = "browser-blocked-a", outcome: str = "pass") -> dict:
    return _case(case_id, "browser-blocked", outcome=outcome, benign=False)


def _latency() -> dict:
    return summarize_hook_latency([{"elapsed_ms": 50.0, "event": "PreToolUse", "http_status": 200}] * 20)


def test_a_run_without_browser_cases_leaves_every_browser_budget_unmeasured() -> None:
    budgets = browser_budgets([{"id": "read-src", "outcome": "pass", "interruptions": {"benign": True}}])
    assert budgets["unmeasured"] == sorted(BROWSER_BUDGET_NAMES)
    assert all(budgets[name]["observed"] is None for name in BROWSER_BUDGET_NAMES)
    assert budgets["usability_regressions"] == budgets["safety_regressions"] == []
    lines = browser_budget_lines(budgets)
    assert len(lines) == len(BROWSER_BUDGET_NAMES)
    assert all("unmeasured" in line and "browser lane not run" in line for line in lines)


def test_a_clean_browser_run_is_within_every_budget() -> None:
    cases = [
        _quiet(),
        _quiet("browser-quiet-provider-ok", provider_twin="browser-quiet-a"),
        _task(),
        _blocked(),
    ]
    budgets = browser_budgets(cases)
    for name in BROWSER_BUDGET_NAMES:
        assert budgets[name]["status"] == "within", name
        assert budgets[name]["observed"] == 0, name
    assert budgets["unmeasured"] == []


def test_a_paused_quiet_case_is_over_the_false_pause_budget() -> None:
    row = browser_budgets([_quiet(interruptions=2), _quiet("browser-quiet-b")])["browser_false_pauses"]
    assert (row["status"], row["observed"], row["regressions"]) == ("over", 1, ["browser-quiet-a"])


def test_approvals_over_a_task_budget_are_summed() -> None:
    budgets = browser_budgets([_task(rows=3, budget=1), _task("browser-task-b", rows=2, budget=2)])
    row = budgets["browser_approvals_over_budget"]
    assert (row["status"], row["observed"], row["regressions"]) == ("over", 2, ["browser-task-a"])
    assert budgets["usability_regressions"] == ["browser_approvals_over_budget"]


def test_repeat_prompts_and_rows_missing_a_choice_are_over() -> None:
    budgets = browser_budgets([_task(repeat_prompts=1, rows_missing_choice=2)])
    assert budgets["browser_repeat_prompts"]["status"] == "over"
    assert budgets["browser_rows_missing_a_choice"]["observed"] == 2
    assert budgets["usability_regressions"] == ["browser_repeat_prompts", "browser_rows_missing_a_choice"]


def test_a_provider_that_adds_a_prompt_over_its_twin_is_over() -> None:
    cases = [_quiet(), _quiet("browser-quiet-provider-ok", provider_twin="browser-quiet-a", interruptions=1)]
    row = browser_budgets(cases)["browser_provider_added_prompts"]
    assert (row["status"], row["observed"], row["regressions"]) == ("over", 1, ["browser-quiet-provider-ok"])


def test_a_provider_case_without_its_twin_is_unmeasured() -> None:
    row = browser_budgets([_quiet("browser-quiet-provider-ok", provider_twin="browser-quiet-a")])[
        "browser_provider_added_prompts"
    ]
    assert row["status"] == "unmeasured"


def test_a_budget_without_cases_in_a_browser_run_does_not_blame_the_lane() -> None:
    lines = browser_budget_lines(browser_budgets([_quiet()]))
    provider = next(line for line in lines if line.startswith("| Provider-added prompts"))
    assert "no measured cases" in provider
    assert not any("browser lane not run" in line for line in lines)


def test_a_failed_browser_protection_case_is_a_safety_regression() -> None:
    budgets = browser_budgets([_blocked(outcome="false-negative")])
    assert budgets["browser_protection_cases"]["status"] == "over"
    assert budgets["safety_regressions"] == ["browser_protection_cases"]
    assert budgets["usability_regressions"] == []
    gapped = browser_budgets([_blocked(outcome="false-negative")], {"browser-blocked-a"})
    assert gapped["browser_protection_cases"]["status"] == "within"


@pytest.mark.parametrize("outcome", ["not-exercised", "inference-error", "harness-error"])
def test_an_inconclusive_case_keeps_its_budget_unmeasured(outcome: str) -> None:
    budgets = browser_budgets([_quiet(outcome=outcome), _blocked(outcome=outcome)])
    assert budgets["browser_false_pauses"]["status"] == "unmeasured"
    assert budgets["browser_protection_cases"]["status"] == "unmeasured"
    assert budgets["browser_protection_cases"]["inconclusive"] == ["browser-blocked-a"]


def test_per_driver_rates_are_reported() -> None:
    cases = [
        _task(rows=2, budget=2),
        _task("browser-task-b", rows=0, budget=1),
        _quiet(),
        _quiet("browser-quiet-b", interruptions=1),
        _case("browser-quiet-c", "browser-quiet", driver_id="sitehand", interruptions=0),
    ]
    drivers = browser_budgets(cases)["drivers"]
    assert drivers["playwright-mcp"] == {
        "completed_tasks": 2,
        "approvals_per_completed_task": 1.0,
        "quiet_cases": 2,
        "quiet_case_rate": 0.5,
    }
    assert drivers["sitehand"]["quiet_case_rate"] == 1.0
    assert drivers["sitehand"]["approvals_per_completed_task"] is None


def test_release_budgets_carry_the_browser_section_into_the_report() -> None:
    cases = [_quiet(interruptions=1), _blocked(outcome="false-negative")]
    budgets = release_budgets(cases, {"benign_interruptions": 0}, _latency())
    assert budgets["browser"]["browser_false_pauses"]["status"] == "over"
    assert "browser_false_pauses" in budgets["usability_regressions"]
    assert budgets["safety_regressions"] is True
    lines = "\n".join(budget_lines(budgets))
    assert "| Browser false pauses | usability | over | 1 in 1 cases | 0 |" in lines
    assert "| Browser protection cases | safety | over | 1 in 1 cases | 0 |" in lines


def test_a_core_run_reports_browser_budgets_as_unmeasured_without_failing() -> None:
    cases = [{"id": "read-src", "outcome": "pass", "interruptions": {"benign": True, "events": []}}]
    budgets = release_budgets(cases, {"benign_interruptions": 0}, _latency())
    assert budgets["safety_regressions"] is False
    assert budgets["usability_regressions"] == []
    assert budgets["unmeasured"] == []
    assert budgets["browser"]["unmeasured"] == sorted(BROWSER_BUDGET_NAMES)
    assert "browser lane not run" in "\n".join(budget_lines(budgets))
