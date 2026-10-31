"""A declared benign exit answers the same way on every lane that can run it.

`benign_exit_commands` names a command whose nonzero exit *is* the answer the
task asked for. Oh My Pi's judge already reads it that way. A `native-tools`
case naming only `bash` also runs on Claude Code, Codex and Cursor, where the
harness reports the same exit as a failed tool call, so without this the case
would fail on those lanes for doing exactly what it was written to do.
"""

from __future__ import annotations

import pytest

from ci.gauntlet.catalog import load_catalog
from ci.gauntlet.harness_judge import assess_harness_case
from ci.gauntlet.harness_suite import lane_catalog
from ci.gauntlet.proofs import required_checks

HARNESSES = ("claude-code", "codex", "cursor")


def _scenario():
    declared = [s for s in load_catalog() if s.benign_exit_commands and s.oracle == "native-tools"]
    assert declared, "no native-tools case declares a benign nonzero exit"
    return declared[0]


def _case(scenario, harness: str, command: str) -> dict:
    """One finished case whose single shell call exited nonzero."""
    return {
        "harness": harness,
        "guard_rows": [
            {
                "route_harness": harness,
                "payload": {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {}},
                "response": {},
                "receipt": {"harness": harness, "event_name": "PreToolUse", "decision": "allow", "reason_code": None},
            }
        ],
        "transcript": {
            "calls": [{"id": "1", "name": "bash", "tool": "bash", "args": {"command": command}, "is_error": True}],
            "terminal": True,
            "failed": False,
        },
        "returncode": 0,
        "filesystem": dict.fromkeys(required_checks(scenario), True),
        "native_routes": {"native_resident": 1},
        "egress_requests": [],
        "approval_delta": 0,
        "cleanup_ok": True,
        "credentials_seeded": 1,
        "credential_env": [],
        "expected_commands": [],
    }


@pytest.mark.parametrize("harness", HARNESSES)
def test_a_declared_benign_exit_passes_on_a_harness_lane(harness: str) -> None:
    scenario = _scenario()
    assessed = assess_harness_case(scenario, _case(scenario, harness, scenario.benign_exit_commands[0]))
    assert assessed["outcome"] == "pass", assessed


@pytest.mark.parametrize("harness", HARNESSES)
def test_an_undeclared_failure_is_still_an_unfinished_task(harness: str) -> None:
    scenario = _scenario()
    assessed = assess_harness_case(scenario, _case(scenario, harness, "cat missing-file"))
    assert assessed["outcome"] == "task-incomplete", assessed


def test_the_lane_that_can_run_the_declared_case_actually_selects_it() -> None:
    """A screen nobody reaches proves nothing, so pin the selection too."""
    scenario = _scenario()
    for harness in HARNESSES:
        assert scenario.id in {s.id for s in lane_catalog(harness)}, harness
