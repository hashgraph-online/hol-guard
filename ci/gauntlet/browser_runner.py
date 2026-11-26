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
from .interruptions import PRE_TOOL_EVENTS, observation_interruptions

# State presets the lane can seed today. The rest need the grant, saved-decision and provider
# fixtures of later phases.
WIRED_PRESETS = frozenset({"none"})
# A browser prompt that names Guard's own approval center uses this placeholder; the lane renders
# it once the daemon has a port.
GUARD_PORT_PLACEHOLDER = "{{guard_port}}"


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


def later_stops_and_unproven(rows: list[dict[str, Any]], harness: str | None) -> tuple[list[str], list[str]]:
    """Non-allow answers to hook events after the pre-tool review, and answers that prove nothing.

    Pre-tool decisions reach the judge as ``decisions``; every other hook event (post-tool and the
    like) can still stop or warn the agent, so its non-allow answers count as interruptions too.
    """
    stops: list[str] = []
    unproven: list[str] = []
    for row in rows:
        for event in observation_interruptions(row, harness):
            if event["kind"] == "unproven":
                unproven.append(f"{event.get('event') or 'unknown event'}: {event.get('why')}")
            elif event["kind"] == "decision" and event.get("event") not in PRE_TOOL_EVENTS:
                stops.append(
                    f"Guard decided {event.get('decision')} on {event.get('event')} for {event.get('tool')}"
                    f" ({event.get('reason_code')})"
                )
    return stops, unproven


def browser_evidence(case: dict[str, Any], decisions: list[dict[str, Any]]) -> BrowserEvidence:
    """What one browser case left behind, as the browser judge reads it."""
    transcript = case.get("transcript") or {}
    stops, unproven = later_stops_and_unproven(case.get("guard_rows") or [], case.get("harness"))
    return BrowserEvidence(
        finished=bool(transcript.get("terminal")) and not transcript.get("failed") and case.get("returncode") == 0,
        decisions=decisions,
        approval_rows=list(case.get("approval_rows") or []),
        rendered_cards=rendered_cards(case.get("guard_rows") or [], case.get("harness")),
        journal=list(case.get("browser_journal") or []),
        later_stops=stops,
        unproven=unproven,
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
