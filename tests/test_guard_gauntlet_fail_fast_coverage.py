"""What ends a Gauntlet attempt, and what the attempt reports about how far it got.

Fail-fast used to stop at the first non-pass outcome of any kind. Because the
catalog schedules the short protection cases last and model non-compliance
clusters early, every attempt died in roughly the same place: a release sweep of
nine attempts and 345 case-executions touched 55 of 134 ids and never reached a
single false-negative proof. These tests hold the stop rule to product failures
and hold the report to naming the cases it never ran.
"""

from __future__ import annotations

from typing import Any

import pytest

from ci.gauntlet.catalog import Scenario
from ci.gauntlet.qualify import RETRYABLE_OUTCOMES
from ci.gauntlet.runner import PRODUCT_FAILURES, case_coverage, disqualifying
from ci.gauntlet.summary import render_summary_markdown


def _result(outcome: str) -> dict[str, Any]:
    return {"assessment": {"outcome": outcome, "reason": "fixture"}}


@pytest.mark.parametrize("outcome", ["false-positive", "false-negative", "task-incomplete"])
def test_an_outcome_a_fresh_attempt_cannot_clear_ends_this_one(outcome: str) -> None:
    # `task-incomplete` is not a Guard mistake, but the scenario's own required
    # effects are missing and `qualify.retryable` will not run the attempt again.
    assert disqualifying(_result(outcome)) is True


def test_the_stop_rule_and_the_retry_rule_agree() -> None:
    # The two sets partition every outcome: anything a fresh attempt can clear is
    # retried and does not stop, and anything else stops and is never retried.
    assert PRODUCT_FAILURES.isdisjoint(RETRYABLE_OUTCOMES)
    assert PRODUCT_FAILURES | RETRYABLE_OUTCOMES | {"pass"} == {
        "pass",
        "false-positive",
        "false-negative",
        "task-incomplete",
        "not-exercised",
        "inference-error",
        "harness-error",
    }


@pytest.mark.parametrize("outcome", ["pass", "not-exercised", "inference-error", "harness-error"])
def test_everything_else_is_recorded_and_the_attempt_continues(outcome: str) -> None:
    # A model that refused, a provider round that died and a host tool that failed
    # with no Guard deny behind it are all facts about the harness. Stopping on one
    # of them spends the rest of the catalog to learn nothing about Guard.
    assert disqualifying(_result(outcome)) is False


def _scenarios(*ids: str) -> tuple[Scenario, ...]:
    return tuple(
        Scenario(id=name, expectation="allow", oracle="native-tools", prompt="p", required_tools=("bash",))
        for name in ids
    )


def test_coverage_counts_the_catalog_and_names_every_case_that_never_ran() -> None:
    catalog = _scenarios("a", "b", "c", "d")
    selected = catalog
    coverage = case_coverage(selected, catalog, {"a", "c"})
    assert coverage == {
        "catalog_cases": 4,
        "selected_cases": 4,
        "executed_cases": 2,
        "unexecuted_cases": ["b", "d"],
    }


def test_a_complete_run_reports_no_unexecuted_cases() -> None:
    catalog = _scenarios("a", "b")
    assert case_coverage(catalog, catalog, {"a", "b"}) == {
        "catalog_cases": 2,
        "selected_cases": 2,
        "executed_cases": 2,
        "unexecuted_cases": [],
    }


def test_a_targeted_selection_still_reports_the_whole_catalog_size() -> None:
    catalog = _scenarios("a", "b", "c")
    selected = _scenarios("a")
    coverage = case_coverage(selected, catalog, {"a"})
    assert coverage["selected_cases"] == 1
    assert coverage["catalog_cases"] == 3
    assert coverage["unexecuted_cases"] == []


def _report(coverage: dict[str, Any] | None) -> dict[str, Any]:
    report: dict[str, Any] = {
        "platform": "darwin",
        "full_profile": True,
        "merge_qualified": False,
        "hook_latency": {
            "samples": 0,
            "missing_samples": 0,
            "failed_attempts": 0,
            "p50_ms": None,
            "p90_ms": None,
            "p95_ms": None,
            "p99_ms": None,
            "mean_ms": None,
            "max_ms": None,
            "by_event": {},
        },
        "cases": [],
    }
    if coverage is not None:
        report["case_coverage"] = coverage
    return report


def test_the_human_summary_states_how_much_of_the_catalog_ran() -> None:
    markdown = render_summary_markdown(
        _report(
            {
                "catalog_cases": 134,
                "selected_cases": 134,
                "executed_cases": 55,
                "unexecuted_cases": ["secret-file-read"],
            }
        ),
        {"candidate_sha": "0" * 40},
        "0" * 40,
        "omp/1.0.0",
    )
    assert "Cases executed: 55 of 134 selected (134 in catalog)" in markdown
    assert "Never executed: secret-file-read" in markdown


def test_a_complete_run_prints_no_never_executed_line() -> None:
    markdown = render_summary_markdown(
        _report({"catalog_cases": 2, "selected_cases": 2, "executed_cases": 2, "unexecuted_cases": []}),
        {"candidate_sha": "0" * 40},
        "0" * 40,
        "omp/1.0.0",
    )
    assert "Cases executed: 2 of 2 selected" in markdown
    assert "Never executed" not in markdown


def test_a_truncated_run_counts_only_the_cases_that_reached_their_decision() -> None:
    # Three cases declare a decision, one reached it and one did not; the third
    # never ran. Counting the reached cases as "everything but the unexercised"
    # would report two of three and credit a case that never started.
    markdown = render_summary_markdown(
        _report(
            {
                "catalog_cases": 3,
                "selected_cases": 3,
                "executed_cases": 2,
                "unexecuted_cases": ["never-ran"],
                "decision_paths": {
                    "declaring_cases": ["reached", "missed", "never-ran"],
                    "exercised_cases": ["reached"],
                    "unexercised_cases": [{"id": "missed", "missing": ["native_policy_block"]}],
                },
            }
        ),
        {"candidate_sha": "0" * 40},
        "0" * 40,
        "omp/1.0.0",
    )
    assert "Declared decisions reached: 1 of 3 declaring cases" in markdown
    assert "Declared decisions never attempted: 1 of 3 declaring cases never ran" in markdown
    assert "Declared decision not reached: missed (native_policy_block)" in markdown


def test_a_complete_run_states_no_never_attempted_line() -> None:
    markdown = render_summary_markdown(
        _report(
            {
                "catalog_cases": 1,
                "selected_cases": 1,
                "executed_cases": 1,
                "unexecuted_cases": [],
                "decision_paths": {
                    "declaring_cases": ["reached"],
                    "exercised_cases": ["reached"],
                    "unexercised_cases": [],
                },
            }
        ),
        {"candidate_sha": "0" * 40},
        "0" * 40,
        "omp/1.0.0",
    )
    assert "Declared decisions reached: 1 of 1 declaring cases" in markdown
    assert "never attempted" not in markdown


def test_the_summary_reports_decisions_observed_beyond_the_declaring_cases() -> None:
    # Undeclared cases still record the codes their run drove; the run-level
    # report aggregates them so a qualification states what it actually reached.
    markdown = render_summary_markdown(
        _report(
            {
                "catalog_cases": 2,
                "selected_cases": 2,
                "executed_cases": 2,
                "unexecuted_cases": [],
                "decision_paths": {
                    "declaring_cases": ["reached"],
                    "exercised_cases": ["reached"],
                    "unexercised_cases": [],
                    "observed_decisions": ["native_policy_block", "native_policy_warning"],
                },
            }
        ),
        {"candidate_sha": "0" * 40},
        "0" * 40,
        "omp/1.0.0",
    )
    assert "Observed decisions: native_policy_block, native_policy_warning" in markdown


def test_the_summary_reports_observed_decisions_when_no_case_declares() -> None:
    markdown = render_summary_markdown(
        _report(
            {
                "catalog_cases": 1,
                "selected_cases": 1,
                "executed_cases": 1,
                "unexecuted_cases": [],
                "decision_paths": {
                    "declaring_cases": [],
                    "exercised_cases": [],
                    "unexercised_cases": [],
                    "observed_decisions": ["native_policy_warning"],
                },
            }
        ),
        {"candidate_sha": "0" * 40},
        "0" * 40,
        "omp/1.0.0",
    )
    assert "Observed decisions: native_policy_warning" in markdown
