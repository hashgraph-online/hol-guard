"""Every live ``browser-quiet`` tool call also runs in the static gate as an ``allow`` row.

The live Gauntlet only runs on release candidates. A browser call it expects to run quietly must
therefore also be a benign false-positive gate row under the same state preset, so a regression
shows up on the pull request that causes it. Modeled on ``test_gauntlet_native_commands_in_fp_gate``.

Some quiet cases need a state preset the gate cannot seed yet. ``AWAITING_STATE`` lists them with
the preset they wait for; a listed case that gains its row, or a preset that gets wired, fails here
so the entry is removed.
"""

from __future__ import annotations

import json
from pathlib import Path

from ci.gauntlet.browser_cases import BROWSER_CATALOG, QUIET_ORACLE
from tests.benign_fp_gate_browser import WIRED_STATES
from tests.benign_fp_gate_mcp import McpCase, mcp_cases

_GATE = Path(__file__).resolve().parent / "fixtures" / "benign_false_positive_gate.json"

# Quiet case id -> the state preset it needs before its gate row can run.
AWAITING_STATE = {
    "browser-quiet-read-only-tools": "site-grant",
}


def _quiet_calls() -> dict[str, list[tuple[str, str, str]]]:
    """``(server, tool, state)`` of every required call, per quiet case."""
    scenarios = json.loads(BROWSER_CATALOG.read_text(encoding="utf-8"))["scenarios"]
    calls: dict[str, list[tuple[str, str, str]]] = {}
    for scenario in scenarios:
        if scenario.get("oracle") != QUIET_ORACLE:
            continue
        state = scenario.get("browser_fixture", "none")
        for tool in scenario.get("required_tools") or []:
            _, server, name = tool.split("__", 2)
            calls.setdefault(scenario["id"], []).append((server, name, state))
    return calls


def _allow_rows() -> set[tuple[str, str, str]]:
    cases: list[McpCase] = mcp_cases(json.loads(_GATE.read_text(encoding="utf-8")))
    return {(case.server, case.tool, case.state) for case in cases if case.expect == "allow"}


def _unpaired() -> dict[str, list[tuple[str, str, str]]]:
    rows = _allow_rows()
    unpaired = {}
    for case_id, calls in _quiet_calls().items():
        missing = [call for call in calls if call not in rows]
        if missing:
            unpaired[case_id] = missing
    return unpaired


def test_the_catalog_has_quiet_browser_cases() -> None:
    assert _quiet_calls(), "no browser-quiet cases found in the browser catalog"


def test_every_quiet_browser_call_has_an_allow_row_in_the_gate() -> None:
    missing = {case_id: calls for case_id, calls in _unpaired().items() if case_id not in AWAITING_STATE}
    assert not missing, f"add allow rows (server, tool, state) to the gate's mcp_cases: {missing}"


def test_a_case_awaits_only_an_unwired_preset_it_actually_uses() -> None:
    calls = _quiet_calls()
    for case_id, state in AWAITING_STATE.items():
        assert case_id in calls, f"{case_id} is no longer a quiet browser case; remove it"
        assert state not in WIRED_STATES, f"{state} is wired now; add the rows for {case_id} and remove it"
        assert {call[2] for call in calls[case_id]} == {state}, f"{case_id} does not run under {state}"


def test_an_awaiting_case_that_gained_its_rows_is_removed() -> None:
    stale = sorted(set(AWAITING_STATE) - set(_unpaired()))
    assert not stale, f"these cases now have allow rows; remove them from AWAITING_STATE: {stale}"
