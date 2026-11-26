"""Stage and collect one ``browser`` profile case for the harness lane (PRD 8.4).

``harness_case.run_harness_case`` calls three things from here:

- ``stage_browser_case`` installs both driver stand-ins and the browser binary before the agent
  starts. Only the ``none`` state preset is wired; a case that needs another preset or a fixture
  provider fails before the agent runs, so it never reads as a pass.
- ``browser_evidence`` turns what the case left behind into ``browser_judge.BrowserEvidence``.
- ``browser_section`` writes the ``browser`` section the release budgets grade.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .browser_cases import BROWSER_PROFILE, TASK_ORACLE
from .browser_fixtures import BrowserFixture, stage_browser_fixture
from .browser_judge import BrowserEvidence, interruptions, repeated_rows, rows_missing_a_choice, tool_name
from .catalog import Scenario
from .interruptions import observation_interruptions

# State presets the lane can seed today. The rest need the grant, saved-decision and provider
# fixtures of later phases.
WIRED_PRESETS = frozenset({"none"})


def is_browser_case(scenario: Scenario) -> bool:
    return BROWSER_PROFILE in scenario.profiles


def stage_browser_case(scenario: Scenario, home: Path, output: Path, harness: str) -> BrowserFixture:
    """Install the browser fixture, or refuse a case whose state the lane cannot seed yet."""
    preset = scenario.browser_fixture or "none"
    if preset not in WIRED_PRESETS:
        raise ValueError(f"browser state preset {preset!r} is not wired into the harness lane yet")
    if scenario.provider_script is not None:
        raise ValueError(f"browser provider script {scenario.provider_script!r} is not wired into the harness lane yet")
    return stage_browser_fixture(home, output, harness)


def rendered_cards(rows: list[dict[str, Any]], harness: str | None) -> int:
    """Hook rows whose answer carried text the harness renders to the agent."""
    return sum(
        1 for row in rows if any(event["kind"] == "rendered" for event in observation_interruptions(row, harness))
    )


def browser_evidence(case: dict[str, Any], decisions: list[dict[str, Any]]) -> BrowserEvidence:
    """What one browser case left behind, as the browser judge reads it."""
    transcript = case.get("transcript") or {}
    return BrowserEvidence(
        finished=bool(transcript.get("terminal")) and not transcript.get("failed") and case.get("returncode") == 0,
        decisions=decisions,
        approval_rows=list(case.get("approval_rows") or []),
        rendered_cards=rendered_cards(case.get("guard_rows") or [], case.get("harness")),
        journal=list(case.get("browser_journal") or []),
    )


def driver_id(scenario: Scenario) -> str:
    """The driver a case runs against: the server of its first tool."""
    return scenario.required_tools[0].split("__", 2)[1]


def browser_section(scenario: Scenario, evidence: BrowserEvidence) -> dict[str, Any]:
    """The ``browser`` section of one case, in the shape ``browser_budgets`` grades."""
    ran = {tool_name(entry) for entry in evidence.journal}
    section: dict[str, Any] = {
        "oracle": scenario.oracle,
        "driver_id": driver_id(scenario),
        "state": scenario.browser_fixture or "none",
        "interruptions": len(interruptions(evidence)),
        "approval_rows": len(evidence.approval_rows),
        "repeat_prompts": len(repeated_rows(evidence.approval_rows)),
        "rows_missing_choice": len(rows_missing_a_choice(evidence.approval_rows)),
        "completed": evidence.finished and all(tool in ran for tool in scenario.required_tools),
        "calls_ran": len(evidence.journal),
    }
    if scenario.oracle == TASK_ORACLE:
        section["approval_budget"] = scenario.approval_budget
    return section
