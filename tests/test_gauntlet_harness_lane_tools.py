"""Each harness lane reaches every case its own tools can drive.

A false positive the Gauntlet never provokes is one nobody sees. The shell
spelling of a read and the harness's own read tool are different requests to
Guard, so a lane that only ever runs shell commands cannot report on the calls
Claude Code or Cursor actually make.
"""

from __future__ import annotations

import pytest

from ci.gauntlet.catalog import load_catalog
from ci.gauntlet.harness_judge import assess_harness_case
from ci.gauntlet.harness_suite import lane_catalog
from ci.gauntlet.harnesses import adapter, claude_tools
from ci.gauntlet.proofs import required_checks

# Oh My Pi's own tools. No other lane has anything to map them onto.
OMP_ONLY = {"glob", "grep", "eval", "task", "wait", "todo", "learn"}


def _native_tools_cases() -> tuple:
    return tuple(s for s in load_catalog() if s.oracle == "native-tools")


@pytest.mark.parametrize("harness", ["claude-code", "cursor"])
def test_structured_read_cases_run_on_lanes_with_a_read_tool(harness: str) -> None:
    selected = {s.id for s in lane_catalog(harness)}
    reads = [s for s in _native_tools_cases() if set(s.required_tools) <= {"bash", "read", "write", "edit"}]
    assert reads, "no structured-tool cases in the catalog"
    missing = sorted(s.id for s in reads if s.id not in selected)
    assert not missing, f"{harness} can drive these tools but the lane skips the cases: {missing}"


def test_codex_keeps_the_shell_only_selection() -> None:
    selected = {s.id for s in lane_catalog("codex")}
    structured = [s for s in _native_tools_cases() if set(s.required_tools) - {"bash"} and s.id in selected]
    assert not structured, "Codex has no structured read, write or edit tool"


@pytest.mark.parametrize("harness", ["claude-code", "codex", "cursor"])
def test_no_lane_claims_an_oh_my_pi_only_tool(harness: str) -> None:
    selected = {s.id for s in lane_catalog(harness)}
    claimed = sorted(s.id for s in _native_tools_cases() if s.id in selected and set(s.required_tools) & OMP_ONLY)
    assert not claimed, f"{harness} has no tool for: {claimed}"


@pytest.mark.parametrize("harness", ["claude-code", "codex", "cursor"])
def test_memory_note_cases_stay_on_oh_my_pi(harness: str) -> None:
    selected = {s.id for s in lane_catalog(harness)}
    notes = sorted(s.id for s in load_catalog() if s.oracle == "blocked-memory-note" and s.id in selected)
    assert not notes, f"{harness} has no memory-note tool: {notes}"


def _granted(scenario) -> set[str]:
    """The catalog tool names Claude Code is handed for one case."""
    names = {"Bash": "bash", "Read": "read", "Write": "write", "Edit": "edit"}
    return {names[name] for name in claude_tools(scenario).split(",")}


def test_a_case_that_also_names_commands_still_gets_its_structured_tools() -> None:
    """Granting Bash alone would leave the structured call impossible to make.

    Three selected cases list shell commands beside a read or a write. The
    commands add Bash to the tools the case names; they do not replace them.
    """
    mixed = [s for s in lane_catalog("claude-code") if s.oracle == "native-tools" and s.commands]
    assert mixed, "no native-tools case lists commands"
    for scenario in mixed:
        granted = _granted(scenario)
        assert set(scenario.required_tools) <= granted, scenario.id
        assert "bash" in granted, scenario.id


def test_every_selected_case_is_handed_the_tools_it_requires() -> None:
    for scenario in lane_catalog("claude-code"):
        if scenario.oracle == "native-tools":
            assert set(scenario.required_tools) <= _granted(scenario), scenario.id


def _allow_row(tool: str, harness: str) -> dict:
    """One quiet Guard review of a call the harness made."""
    name = {"bash": "Bash", "read": "Read", "write": "Write", "edit": "Edit"}[tool]
    return {
        "route_harness": harness,
        "payload": {"hook_event_name": "PreToolUse", "tool_name": name, "tool_input": {}},
        "response": {},
        "receipt": {"harness": harness, "event_name": "PreToolUse", "decision": "allow", "reason_code": None},
    }


def _case(scenario, tools: tuple[str, ...], harness: str = "claude-code") -> dict:
    """One finished case whose transcript used exactly ``tools``."""
    return {
        "harness": harness,
        "guard_rows": [_allow_row(tool, harness) for tool in tools],
        "transcript": {
            "calls": [
                {"id": str(i), "name": tool, "tool": tool, "args": {}, "is_error": False}
                for i, tool in enumerate(tools)
            ],
            "terminal": True,
            "failed": False,
        },
        "returncode": 0,
        "filesystem": dict.fromkeys(required_checks(scenario), True),
        "native_routes": {"native_resident": len(tools)},
        "egress_requests": [],
        "approval_delta": 0,
        "cleanup_ok": True,
        "credentials_seeded": 1,
        "credential_env": [],
        "expected_commands": [],
    }


def test_a_shell_fallback_does_not_pass_as_a_structured_read() -> None:
    """Reading through the shell is a different request from the read tool.

    Without this the lane could report a structured read it never made, which
    is the whole reason these cases run here.
    """
    scenario = next(s for s in lane_catalog("claude-code") if s.oracle == "native-tools" and "read" in s.required_tools)
    shell_only = assess_harness_case(scenario, _case(scenario, ("bash",)))
    assert shell_only["outcome"] == "not-exercised"
    assert "read" in shell_only["reason"]
    used = assess_harness_case(scenario, _case(scenario, tuple(scenario.required_tools)))
    assert used["outcome"] == "pass"


def test_a_lane_without_a_tool_is_not_held_to_a_name_it_cannot_call() -> None:
    """``required_tools`` outside ``native-tools`` is Oh My Pi's grant list.

    Codex does its reading and writing through the shell, and ``lane_catalog``
    still hands it the task cases. Screening their tool names would fail those
    cases on every run for a tool the lane has never had.
    """
    scenario = next(
        s
        for s in lane_catalog("codex")
        if s.oracle in {"settings-task", "home-task", "home-copy-task"}
        and set(s.required_tools) - adapter("codex").native_tools
    )
    assessed = assess_harness_case(scenario, _case(scenario, ("bash",), harness="codex"))
    assert assessed["outcome"] == "pass", assessed
