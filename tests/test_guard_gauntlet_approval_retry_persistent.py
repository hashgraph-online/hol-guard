"""The persistent-approval case recognises its own action and nothing else."""

from __future__ import annotations

import json
import shlex
from pathlib import Path

from ci.gauntlet.approval_retry_persistent import (
    CASE,
    CASE_COMMAND,
    assessment,
    persistent_consent,
    targets_case_command,
)

CATALOG = Path(__file__).resolve().parents[1] / "ci" / "gauntlet" / "approval_retry.json"
# The run count the prompt asks the agent to report. It names the same words as
# the pinned action without being it.
A_REPORTING_READ = "git config --file persistent-approval-runs.txt --get-all gauntlet.run"


def test_the_pinned_argv_is_the_catalog_command() -> None:
    scenarios = json.loads(CATALOG.read_text())["scenarios"]
    case = next(scenario for scenario in scenarios if scenario["id"] == CASE)
    assert tuple(shlex.split(case["commands"][0])) == CASE_COMMAND


def test_a_read_that_names_the_same_key_is_not_the_case_command() -> None:
    assert targets_case_command(shlex.join(CASE_COMMAND))
    assert not targets_case_command(A_REPORTING_READ)
    assert not persistent_consent(CASE, A_REPORTING_READ)
    assert not targets_case_command("git config --file persistent-approval-runs.txt --add gauntlet.run ok extra")
    assert not targets_case_command("git config --file 'unclosed")


def _case(runs: int, targets: list[str]) -> dict[str, object]:
    return {
        "persistent_approval": {"initially_absent": True, "runs": runs},
        "approval_grants": {"granted": [{"target": target, "persist_policy": True} for target in targets]},
    }


def test_a_reviewed_reporting_read_does_not_fail_the_case() -> None:
    pinned = shlex.join(CASE_COMMAND)
    outcome = assessment(CASE, _case(3, [pinned, A_REPORTING_READ]), ("pass", "ran three times"))
    assert outcome == ("pass", "ran three times")


def test_a_second_review_of_the_pinned_action_still_fails() -> None:
    pinned = shlex.join(CASE_COMMAND)
    verdict, detail = assessment(CASE, _case(3, [pinned, pinned]), ("pass", "ran three times"))
    assert verdict == "fail"
    assert "reviewed 2 times" in detail
