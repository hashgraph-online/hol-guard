"""Tests for how exported host events mark the end of an agent session."""

import json

from ci.gauntlet.case_helpers import read_case_logs
from ci.gauntlet.evidence import public_events

AWAITING_JOB = {"type": "agent_end", "isTerminal": False, "yielded": True, "awaitingAsyncWork": True}


def ends(events, completed=True):
    exported = public_events(events, {}, completed)
    return [event["terminal"] for event in exported if event["type"] == "agent_end"]


def test_terminal_end_is_terminal():
    assert ends([{"type": "agent_end", "isTerminal": True}]) == [True]


def test_final_end_awaiting_only_a_background_job_is_terminal():
    """A dev server left running does not keep a finished print session open."""
    assert ends([{"type": "message_end", "message": {"role": "assistant"}}, AWAITING_JOB]) == [True]


def test_end_awaiting_a_job_that_wakes_the_agent_is_not_terminal():
    later = [{"type": "agent_start"}, {"type": "agent_end", "isTerminal": True}]
    assert ends([AWAITING_JOB, *later]) == [False, True]


def test_continuations_the_agent_scheduled_are_not_terminal():
    retry = {"type": "agent_end", "isTerminal": False, "yielded": False}
    queued = {"type": "agent_end", "isTerminal": False, "yielded": True}
    unyielded_job = {**AWAITING_JOB, "yielded": False}
    assert ends([retry]) == ends([queued]) == ends([unyielded_job]) == [False]


def test_end_awaiting_a_job_is_not_terminal_when_the_process_did_not_finish():
    """A killed or failed print run may have stopped before the job woke the agent."""
    events = [{"type": "message_end", "message": {"role": "assistant"}}, AWAITING_JOB]
    assert ends(events, completed=False) == [False]


def test_each_print_run_settles_on_its_own():
    """A later batch's start does not reopen an earlier, already disposed print session."""
    first = [{"type": "agent_start"}, AWAITING_JOB]
    second = [{"type": "agent_start"}, {"type": "agent_end", "isTerminal": True}]
    assert ends(first) + ends(second) == [True, True]


def test_case_logs_upgrade_awaiting_ends_only_for_a_clean_exit(tmp_path):
    raw_log = tmp_path / "omp.jsonl"
    raw_log.write_text(json.dumps(AWAITING_JOB) + "\n")
    cases = [
        {"returncode": 0, "timed_out": False},
        {"returncode": 0, "timed_out": True},
        {"returncode": 1, "timed_out": False},
    ]
    for case in cases:
        read_case_logs(case, raw_log, tmp_path / "absent.jsonl", {})
    assert [case["events"][0]["terminal"] for case in cases] == [True, False, False]
