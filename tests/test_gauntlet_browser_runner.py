"""The harness lane stages, judges and reports browser cases; no live agent runs here."""

from __future__ import annotations

import dataclasses
from pathlib import Path
from typing import Any

import pytest

from ci.gauntlet.browser_cases import BROWSER_CATALOG
from ci.gauntlet.browser_judge import BrowserEvidence, browser_outcome
from ci.gauntlet.browser_runner import (
    browser_evidence,
    browser_section,
    driver_id,
    rendered_cards,
    stage_browser_case,
)
from ci.gauntlet.catalog import load_catalog
from ci.gauntlet.fixtures import scenario_fixture_name
from ci.gauntlet.harness_judge import assess_harness_case, guard_decisions
from ci.gauntlet.proofs import required_checks

_SCENARIOS = {scenario.id: scenario for scenario in load_catalog(BROWSER_CATALOG)}
_QUIET = _SCENARIOS["browser-quiet-read-only-tools"]
_BLOCKED = _SCENARIOS["browser-blocked-guard-origin"]


def _receipt(tool: str, decision: str, reason: str) -> dict[str, Any]:
    return {
        "payload": {"hook_event_name": "PreToolUse", "tool_name": tool, "tool_use_id": tool},
        "receipt": {"event_name": "PreToolUse", "decision": decision, "harness": "claude-code", "reason_code": reason},
        "response": {"hookSpecificOutput": {"permissionDecision": decision}} if decision == "deny" else {},
    }


def _case(rows: list[dict[str, Any]], journal: list[dict[str, Any]], **extra: Any) -> dict[str, Any]:
    proofs = required_checks(_QUIET) | required_checks(_BLOCKED)
    return {
        "harness": "claude-code",
        "filesystem": dict.fromkeys(proofs, True),
        "cleanup_ok": True,
        "credentials_seeded": 1,
        "returncode": 0,
        "native_routes": {"native_resident": len(rows)},
        "transcript": {"terminal": True, "calls": [{"tool": "mcp"}]},
        "guard_rows": rows,
        "approval_rows": [],
        "browser_journal": journal,
        **extra,
    }


def test_an_unwired_state_preset_fails_before_the_agent_runs(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="'site-grant' is not wired"):
        stage_browser_case(_QUIET, tmp_path / "home", tmp_path / "out", "claude-code")


def test_a_provider_script_fails_before_the_agent_runs(tmp_path: Path) -> None:
    scenario = dataclasses.replace(_BLOCKED, provider_script="ok")
    with pytest.raises(ValueError, match="provider script 'ok' is not wired"):
        stage_browser_case(scenario, tmp_path / "home", tmp_path / "out", "claude-code")


def test_the_none_preset_stages_the_driver_for_the_harness(tmp_path: Path) -> None:
    fixture = stage_browser_case(_BLOCKED, tmp_path / "home", tmp_path / "out", "cursor")
    assert fixture.mcp_configs == (tmp_path / "home" / ".cursor" / "mcp.json",)
    assert fixture.call_journal == tmp_path / "out" / "browser-calls.jsonl"


def test_a_stopped_protected_call_on_its_path_passes_and_reports_its_section() -> None:
    case = _case([_receipt("mcp__playwright__browser_navigate", "deny", "browser_guard_origin")], [])
    case["browser"] = browser_section(_BLOCKED, browser_evidence(case, guard_decisions(case["guard_rows"])))
    scenario = dataclasses.replace(_BLOCKED, decision_paths=("browser_guard_origin",))
    assessment = assess_harness_case(scenario, case)
    assert (assessment["outcome"], assessment["reason"]) == (
        "pass",
        "Guard stopped mcp__playwright__browser_navigate on browser_guard_origin",
    )
    assert case["browser"]["oracle"] == "browser-blocked"
    assert case["browser"]["driver_id"] == "playwright"
    assert case["browser"]["interruptions"] == 1


def test_a_protected_call_in_the_journal_is_a_false_negative() -> None:
    journal = [{"server": "playwright", "tool": "browser_navigate"}]
    case = _case([_receipt("mcp__playwright__browser_navigate", "allow", "allowed")], journal)
    assert assess_harness_case(_BLOCKED, case)["outcome"] == "false-negative"


def test_a_quiet_case_with_an_approval_row_is_a_false_positive() -> None:
    journal = [{"server": "playwright", "tool": "browser_snapshot"}]
    rows = [_receipt("mcp__playwright__browser_snapshot", "allow", "allowed")]
    case = _case(rows, journal, approval_rows=[{"tool_name": "mcp__playwright__browser_snapshot"}])
    assessment = assess_harness_case(_QUIET, case)
    assert (assessment["outcome"], assessment["reason"]) == ("false-positive", "1 approval row(s) created")
    section = browser_section(_QUIET, browser_evidence(case, []))
    assert section["interruptions"] == 1
    assert section["completed"] is False


@pytest.mark.parametrize("scenario", [_QUIET, dataclasses.replace(_QUIET, oracle="browser-task", approval_budget=1)])
def test_a_journaled_call_with_no_guard_decision_is_a_harness_error(scenario: Any) -> None:
    journal = [{"server": "playwright", "tool": tool.split("__", 2)[2]} for tool in scenario.required_tools]
    evidence = BrowserEvidence(finished=True, journal=journal)
    outcome, reason = browser_outcome(scenario, evidence)
    assert outcome == "harness-error"
    assert "with no Guard decision" in reason


def test_an_execution_error_stays_a_harness_error() -> None:
    case = _case([], [], execution_error="ValueError")
    assert assess_harness_case(_QUIET, case)["outcome"] == "harness-error"


def test_rendered_text_counts_as_a_card() -> None:
    row = _receipt("mcp__playwright__browser_snapshot", "allow", "allowed")
    row["response"] = {"systemMessage": "Guard noticed this page"}
    assert rendered_cards([row, _receipt("x", "allow", "allowed")], "claude-code") == 1


def test_the_driver_is_the_server_of_the_first_tool() -> None:
    assert driver_id(_QUIET) == "playwright"


def test_every_browser_case_has_its_own_fixture_directory() -> None:
    names = {scenario_fixture_name(case_id) for case_id in _SCENARIOS}
    assert len(names) == len(_SCENARIOS)
    assert scenario_fixture_name("secret-file-read") not in names


def _quiet_run() -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    rows = [_receipt(tool, "allow", "allowed") for tool in _QUIET.required_tools]
    journal = [{"server": "playwright", "tool": tool.split("__", 2)[2]} for tool in _QUIET.required_tools]
    return rows, journal


def test_the_quiet_baseline_passes() -> None:
    rows, journal = _quiet_run()
    assert assess_harness_case(_QUIET, _case(rows, journal))["outcome"] == "pass"


def test_a_post_tool_stop_is_a_quiet_interruption() -> None:
    rows, journal = _quiet_run()
    tool = _QUIET.required_tools[0]
    rows.append(
        {
            "payload": {"hook_event_name": "PostToolUse", "tool_name": tool, "tool_use_id": tool},
            "receipt": {"event_name": "PostToolUse", "harness": "claude-code", "reason_code": "output_blocked"},
            "response": {"decision": "block"},
        }
    )
    case = _case(rows, journal)
    assessment = assess_harness_case(_QUIET, case)
    assert assessment["outcome"] == "false-positive"
    assert "PostToolUse" in assessment["reason"]
    evidence = browser_evidence(case, guard_decisions(rows))
    assert browser_section(_QUIET, evidence)["interruptions"] == 1
    task = dataclasses.replace(_QUIET, oracle="browser-task", approval_budget=1)
    assert browser_outcome(task, evidence)[0] == "false-positive"


def test_an_unproven_hook_answer_fails_a_quiet_case_as_a_harness_error() -> None:
    rows, journal = _quiet_run()
    rows.append({"event": "PostToolUse", "transport_error": "reset"})
    assessment = assess_harness_case(_QUIET, _case(rows, journal))
    assert assessment["outcome"] == "harness-error"
    assert "could not prove it was quiet" in assessment["reason"]


def test_a_later_stop_before_any_browser_call_fails_a_task_case() -> None:
    task = dataclasses.replace(_QUIET, oracle="browser-task", approval_budget=1)
    stopped = BrowserEvidence(finished=False, later_stops=["Guard decided deny on PostToolUse for Read (blocked)"])
    assert browser_outcome(task, stopped) == ("false-positive", stopped.later_stops[0])
    assert browser_outcome(task, BrowserEvidence(finished=False))[0] == "not-exercised"
