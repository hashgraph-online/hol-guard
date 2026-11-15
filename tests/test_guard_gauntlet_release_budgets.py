"""Release budget contracts; these tests do not qualify a live agent run."""

from __future__ import annotations

import json

from ci.gauntlet.latency import summarize_hook_latency
from ci.gauntlet.release_budgets import (
    PRE_TOOL_P95_BUDGET_MS,
    attempt_observations,
    budget_lines,
    release_budgets,
)


def _case(case_id: str, *, benign: bool, outcome: str = "pass", events: list | None = None) -> dict:
    return {"id": case_id, "outcome": outcome, "interruptions": {"benign": benign, "events": events or []}}


def _latency(pre_tool_ms: float, *, failed: bool = False) -> dict:
    rows = [{"elapsed_ms": pre_tool_ms, "event": "PreToolUse", "http_status": 200} for _ in range(20)]
    if failed:
        rows.append({"elapsed_ms": 10.0, "event": "PreToolUse", "transport_error": True})
    return summarize_hook_latency(rows)


def test_a_quiet_fast_run_is_within_every_budget():
    cases = [_case("block-env", benign=False), _case("read-src", benign=True)]
    budgets = release_budgets(cases, {"benign_interruptions": 0}, _latency(80.0))
    assert budgets["safety"]["status"] == "within"
    assert budgets["false_pauses"]["status"] == "within"
    assert budgets["latency"]["status"] == "within"
    assert budgets["safety_regressions"] is False
    assert budgets["usability_regressions"] == []
    assert budgets["unmeasured"] == []


def test_a_missed_block_is_a_safety_regression_not_a_usability_one():
    cases = [_case("block-env", benign=False, outcome="fail"), _case("read-src", benign=True)]
    budgets = release_budgets(cases, {"benign_interruptions": 0}, _latency(80.0))
    assert budgets["safety_regressions"] is True
    assert budgets["safety"]["regressions"] == ["block-env"]
    assert budgets["usability_regressions"] == []


def test_a_known_gap_is_not_counted_as_a_new_safety_regression():
    cases = [_case("block-env", benign=False, outcome="fail")]
    budgets = release_budgets(cases, {"benign_interruptions": 0}, _latency(80.0), [{"id": "block-env"}])
    assert budgets["safety"]["status"] == "within"


def test_a_paused_benign_case_is_a_false_pause_regression():
    events = [{"kind": "approval", "reason_code": "native_command_review_required"}]
    cases = [_case("block-env", benign=False), _case("git-status", benign=True, events=events)]
    budgets = release_budgets(cases, {"benign_interruptions": 1}, _latency(80.0))
    assert budgets["safety_regressions"] is False
    assert budgets["false_pauses"]["status"] == "over"
    assert budgets["false_pauses"]["regressions"] == ["git-status"]
    assert budgets["usability_regressions"] == ["false_pauses"]


def test_a_slow_pre_tool_hook_is_a_latency_regression():
    budgets = release_budgets([_case("read-src", benign=True)], {"benign_interruptions": 0}, _latency(1500.0))
    assert budgets["latency"]["status"] == "over"
    assert budgets["latency"]["regressions"] == ["pre_tool_p95"]
    assert budgets["latency"]["p95_budget_ms"] == PRE_TOOL_P95_BUDGET_MS
    assert budgets["usability_regressions"] == ["latency"]


def test_a_failed_hook_attempt_is_over_budget_even_when_fast():
    budgets = release_budgets([_case("read-src", benign=True)], {"benign_interruptions": 0}, _latency(5.0, failed=True))
    assert budgets["latency"]["regressions"] == ["failed_hook_attempts"]


def test_missing_timings_and_cases_are_unmeasured_never_within():
    budgets = release_budgets([], {}, summarize_hook_latency([]))
    assert budgets["false_pauses"]["status"] == "unmeasured"
    assert budgets["latency"]["status"] == "unmeasured"
    assert budgets["unmeasured"] == ["false_pauses", "latency"]


def test_the_summary_names_each_budget_and_an_absent_section():
    budgets = release_budgets([_case("read-src", benign=True)], {"benign_interruptions": 0}, _latency(1500.0))
    text = "\n".join(budget_lines(budgets))
    assert "| PreToolUse p95 | usability | over | 1500.0 ms (20 samples) | 1000.0 ms |" in text
    assert "| Failed hook attempts (all attempts) | usability | within | 0 | 0 |" in text
    assert "| Protection cases | safety | within | 0 failed of 0 | 0 |" in text
    assert budget_lines(None)[0] == "Release budgets: not reported"


def test_a_harness_or_inference_failure_is_inconclusive_not_a_regression():
    cases = [
        _case("block-env", benign=False, outcome="inference-error"),
        _case("read-src", benign=True, outcome="harness-error"),
    ]
    budgets = release_budgets(cases, {"benign_interruptions": 0}, _latency(80.0))
    assert budgets["safety_regressions"] is False
    assert budgets["safety"]["inconclusive"] == ["block-env"]
    assert budgets["false_pauses"]["regressions"] == []
    assert budgets["false_pauses"]["inconclusive"] == ["read-src"]
    assert budgets["usability_regressions"] == []
    assert budgets["unmeasured"] == ["false_pauses", "safety"]
    text = "\n".join(budget_lines(budgets))
    assert "0 failed of 1, 1 inconclusive" in text


def test_an_unfinished_benign_task_is_a_usability_regression_even_without_a_pause():
    cases = [_case("read-src", benign=True, outcome="task-incomplete")]
    budgets = release_budgets(cases, {"benign_interruptions": 0}, _latency(80.0))
    assert budgets["false_pauses"]["status"] == "over"
    assert budgets["false_pauses"]["regressions"] == ["read-src"]
    assert budgets["false_pauses"]["inconclusive"] == []


def test_a_failed_hook_in_a_superseded_attempt_still_counts(tmp_path):
    (tmp_path / "cases").mkdir()
    (tmp_path / "superseded").mkdir()
    ok = {"elapsed_ms": 5.0, "event": "PreToolUse", "http_status": 200}
    failed = {"elapsed_ms": 5.0, "event": "PreToolUse", "transport_error": True}
    (tmp_path / "cases" / "read-src.json").write_text(json.dumps({"guard_observations": [ok]}))
    (tmp_path / "superseded" / "read-src.attempt-1.json").write_text(json.dumps({"guard_observations": [failed]}))
    history = [{"id": "read-src", "attempt": 1, "evidence": "read-src.attempt-1.json"}]
    observations = attempt_observations(tmp_path, ["read-src"], history)
    budgets = release_budgets(
        [_case("read-src", benign=True)], {"benign_interruptions": 0}, summarize_hook_latency(observations)
    )
    assert budgets["latency"]["regressions"] == ["failed_hook_attempts"]
