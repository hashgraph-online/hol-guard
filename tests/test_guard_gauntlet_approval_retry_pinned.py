"""A pinned approval-retry case passes only when the identical command ran."""

from __future__ import annotations

from ci.gauntlet.approval_retry import pinned_retry_outcome

PINNED = ("LC_ALL=C ls -la",)


def _decision(command: str, decision: str) -> dict[str, str]:
    return {"command": command, "decision": decision}


def test_an_identical_allowed_retry_satisfies_the_pinned_command():
    decisions = [_decision("LC_ALL=C ls -la", "deny"), _decision("LC_ALL=C ls -la", "allow")]
    assert pinned_retry_outcome(PINNED, decisions) is None


def test_a_retry_with_another_setting_or_argument_is_not_the_pinned_command():
    for retry in ("LC_ALL=POSIX ls -la", "LC_ALL=C ls -l", "ls -la"):
        decisions = [_decision("LC_ALL=C ls -la", "deny"), _decision(retry, "allow")]
        outcome = pinned_retry_outcome(PINNED, decisions)
        assert outcome is not None and outcome[0] == "not-exercised", retry


def test_a_case_without_a_pinned_command_is_left_to_the_retry_oracle():
    assert pinned_retry_outcome((), [_decision("git status", "allow")]) is None
