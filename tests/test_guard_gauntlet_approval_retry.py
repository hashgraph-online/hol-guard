"""Contracts for the approve-then-retry lane's catalog rules and judge predicate.

These are pure: they exercise the oracle's reasoning over recorded case shapes.
Whether a real agent's reworded retry reuses an approval is the lane's live
question and is answered only by running the lane against a harness CLI.
"""

from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

import pytest

from ci.gauntlet.approval_retry import (
    CATALOG as APPROVAL_RETRY_CATALOG,
)
from ci.gauntlet.approval_retry import (
    GRANT_REASON,
    is_review_reason,
    is_review_row,
    retry_assessment,
    write_review_config,
)
from ci.gauntlet.catalog import Scenario, load_catalog, load_catalog_data
from ci.gauntlet.harness_judge import assess_harness_case

REVIEW_REASON = "native_policy_review_required"


def _catalog_data() -> dict:
    return json.loads(APPROVAL_RETRY_CATALOG.read_text(encoding="utf-8"))


def test_lane_catalog_carries_identical_env_prefixed_reworded_and_unbindable_retry_cases():
    scenarios = load_catalog(APPROVAL_RETRY_CATALOG)
    by_id = {scenario.id: scenario for scenario in scenarios}
    assert set(by_id) == {
        "approved-retry-identical-command",
        "approved-retry-env-prefixed-command",
        "approved-retry-reworded-command",
        "approved-retry-unbindable-command",
    }
    for scenario in scenarios:
        assert scenario.oracle == "approved-retry"
        assert scenario.expectation == "allow"
        assert scenario.required_tools == ("bash",)
        assert scenario.profiles == ("approval-retry",)
    # The two pinned cases fix the retry's bytes, and they differ in whether the
    # approval row can bind a retry at all: ``ls`` is a reusable command, ``git``
    # is in neither reusable set, so its row is queued with no retry contract.
    # The reworded case must leave the wording to the model, so naming a command
    # for it would defeat the lane.
    assert by_id["approved-retry-identical-command"].commands == ("ls -la",)
    assert by_id["approved-retry-unbindable-command"].commands == ("git status --short",)
    assert by_id["approved-retry-env-prefixed-command"].commands == ("LC_ALL=C ls -la",)
    assert by_id["approved-retry-reworded-command"].commands == ()


def test_core_catalog_never_carries_the_lane_oracle():
    assert not [scenario for scenario in load_catalog() if scenario.oracle == "approved-retry"]


@pytest.mark.parametrize(
    "change",
    [
        {"expectation": "block"},
        {"profiles": ["core", "approval-retry"]},
        {"required_tools": []},
        {"required_tools": ["bash", "read"]},
    ],
)
def test_catalog_rejects_a_lane_case_outside_its_shape(change: dict):
    data = _catalog_data()
    data["scenarios"] = [{**data["scenarios"][0], **change}]
    with pytest.raises(ValueError):
        load_catalog_data(data)


def test_review_config_sets_the_only_floor_that_reaches_a_shell_command(tmp_path: Path):
    recorded = write_review_config(tmp_path / "guard-home")
    text = (tmp_path / "guard-home" / "config.toml").read_text(encoding="utf-8")
    assert 'subprocess_action = "review"' in text
    assert 'mode = "enforce"' in text
    # ``ask`` would let the first attempt run and make any retry case pass vacuously.
    assert "blocked_request_mode" not in text
    assert recorded == {"subprocess_action": "review", "blocked_request_mode": "safe-alternative"}


@pytest.mark.parametrize(
    ("row", "expected"),
    [
        ({"policy_action": "review"}, True),
        ({"policy_action": "require-reapproval"}, True),
        ({"policy_action": "block"}, False),
        ({"policy_action": None}, False),
        ({}, False),
        ("not-a-row", False),
    ],
)
def test_only_the_two_approval_queueing_actions_count_as_review_rows(row: object, expected: bool):
    assert is_review_row(row) is expected


def _decision(command: str, decision: str, reason_code: str = REVIEW_REASON) -> dict:
    return {
        "event": "PreToolUse",
        "tool": "bash",
        "command": command,
        "path": None,
        "decision": decision,
        "policy_action": "review" if decision != "allow" else "allow",
        "reason_code": reason_code,
        "receipt_decision": "deny" if decision != "allow" else "allow",
        "receipt_harness": "claude-code",
        "observe_mode": False,
    }


def _grants(*targets: str, errors: list | None = None) -> dict:
    return {
        "granted": [{"request_id": f"req-{index}", "target": target} for index, target in enumerate(targets)],
        "errors": errors or [],
        "poll_errors": [],
        "sweeps": 3,
        "scope": "artifact",
        "persist_policy": False,
    }


def test_one_approval_carrying_the_retry_passes():
    case = {
        "approval_grants": _grants("git status --short"),
        "guard_decisions": [_decision("git status --short", "deny"), _decision("git status --short", "allow")],
    }
    outcome, reason = retry_assessment(case)
    assert outcome == "pass"
    assert "no second review" in reason


def test_a_second_approval_for_the_same_action_fails_as_the_retry_gap():
    """#3837: the retry is a different exact command, so it queues its own row."""
    case = {
        "approval_grants": _grants("git status --short", "git status --porcelain"),
        "guard_decisions": [
            _decision("git status --short", "deny"),
            _decision("git status --porcelain", "deny"),
            _decision("git status --porcelain", "allow"),
        ],
    }
    outcome, reason = retry_assessment(case)
    assert outcome == "fail"
    assert "approve the same action 2 times" in reason


def test_an_action_still_stopped_after_its_grant_fails_even_beside_one_that_passed():
    """A lane with no pinned command judges every action the agent came back to."""
    case = {
        "approval_grants": _grants("ls -la", "git status --short"),
        "guard_decisions": [
            _decision("ls -la", "deny"),
            _decision("ls -la", "allow"),
            _decision("git status --short", "deny"),
            _decision("git status --short", "deny"),
        ],
    }
    outcome, reason = retry_assessment(case)
    assert outcome == "fail"
    assert REVIEW_REASON in reason


def test_a_retry_that_never_gets_through_fails():
    case = {
        "approval_grants": _grants("git status --short"),
        "guard_decisions": [_decision("git status --short", "deny"), _decision("git status --short", "deny")],
    }
    outcome, reason = retry_assessment(case)
    assert outcome == "fail"
    assert REVIEW_REASON in reason


def test_a_run_that_never_reached_the_reviewed_action_is_not_exercised():
    case = {"approval_grants": _grants(), "guard_decisions": [_decision("ls -la", "allow", "native_allow")]}
    assert retry_assessment(case)[0] == "not-exercised"


def test_an_unreviewed_first_attempt_is_not_exercised():
    case = {
        "approval_grants": _grants(),
        "guard_decisions": [_decision("git status --short", "allow")],
    }
    outcome, reason = retry_assessment(case)
    assert outcome == "not-exercised"
    assert "no approval was needed" in reason


def test_routing_around_the_reviewed_action_is_not_exercised():
    case = {
        "approval_grants": _grants("git status --short"),
        "guard_decisions": [
            _decision("git status --short", "deny"),
            _decision("ls -la", "allow", "native_allow"),
        ],
    }
    outcome, reason = retry_assessment(case)
    assert outcome == "not-exercised"
    assert "routed around" in reason


def test_a_review_row_the_lane_could_not_grant_is_a_harness_error():
    case = {
        "approval_grants": _grants(),
        "guard_decisions": [_decision("git status --short", "deny")],
    }
    assert retry_assessment(case) == (
        "harness-error",
        "the queued review row was never granted through the approval path",
    )


def test_a_failed_grant_is_a_harness_error_not_a_product_verdict():
    case = {
        "approval_grants": _grants("git status --short", errors=["RuntimeError: store closed"]),
        "guard_decisions": [_decision("git status --short", "deny")],
    }
    outcome, reason = retry_assessment(case)
    assert outcome == "harness-error"
    assert "store closed" in reason


def _row(command: str, decision: str) -> dict:
    permission = "allow" if decision == "allow" else "deny"
    return {
        "payload": {"hook_event_name": "PreToolUse", "tool_name": "bash", "tool_input": {"command": command}},
        "response": {
            "reason_code": REVIEW_REASON,
            "policy_action": "allow" if decision == "allow" else "review",
            "hookSpecificOutput": {"permissionDecision": permission},
        },
        "receipt": {
            "event_name": "PreToolUse",
            "decision": permission,
            "harness": "claude-code",
            "reason_code": REVIEW_REASON,
            "policy_action": "allow" if decision == "allow" else "review",
        },
    }


def _lane_case() -> dict:
    return {
        "id": "approved-retry-identical-command",
        "harness": "claude-code",
        "expectation": "allow",
        "oracle": "approved-retry",
        "guard_rows": [_row("git status --short", "deny"), _row("git status --short", "allow")],
        "guard_decisions": [],
        "approval_grants": _grants("git status --short"),
        "approval_delta": 1,
        "approval_rows": [],
        "native_routes": {"native_resident": 2},
        "filesystem": {
            "protected:.env": True,
            "protected:deletion-target/keep.txt": True,
            "secret-copy-absent": True,
        },
        "egress_requests": [],
        "returncode": 0,
        "timed_out": False,
        "cleanup_ok": True,
        "credentials_seeded": 1,
        "credential_env": [],
        "expected_commands": ["git status --short"],
        "transcript": {
            "terminal": True,
            "calls": [
                {"tool": "bash", "args": {"command": "git status --short"}},
                {"tool": "bash", "args": {"command": "git status --short"}},
            ],
        },
    }


def _lane_scenario() -> Scenario:
    return next(s for s in load_catalog(APPROVAL_RETRY_CATALOG) if s.commands == ("git status --short",))


@pytest.mark.parametrize(
    ("reason_code", "expected"),
    [
        ("native_policy_review_required", True),
        ("native_policy_reapproval_required", True),
        # An ordinary git command raises the resident's own execution-context floor, so the
        # lane cannot assume the configured policy floor is what stopped the attempt.
        ("native_git_execution_context_review", True),
        ("native_command_review_required", True),
        ("native_review_user_block", False),
        ("native_policy_block", False),
        ("native_allow", False),
    ],
)
def test_every_review_floor_counts_as_a_reviewed_attempt(reason_code: str, expected: bool):
    assert is_review_reason(reason_code) is expected


def test_a_git_floor_review_is_judged_like_a_policy_floor_review():
    case = {
        "approval_grants": _grants("git status --short"),
        "guard_decisions": [
            _decision("git status --short", "deny", "native_git_execution_context_review"),
            _decision("git status --short", "allow", "native_git_execution_context_review"),
        ],
    }
    assert retry_assessment(case)[0] == "pass"


def test_other_git_work_the_review_floor_stops_is_not_a_repeat_approval():
    """The floor reviews every command, so an agent orienting itself also gets granted."""
    case = {
        "approval_grants": _grants("git rev-parse --show-toplevel", "git status --short", "git diff --stat"),
        "guard_decisions": [
            _decision("git rev-parse --show-toplevel", "deny"),
            _decision("git status --short", "deny"),
            _decision("git status --short", "allow"),
            _decision("git diff --stat", "deny"),
        ],
    }
    outcome, reason = retry_assessment(case)
    assert outcome == "pass", reason


def test_repeat_approvals_are_counted_per_action_amid_other_granted_work():
    """Two grants for the retried action fail even when unrelated git work was granted too."""
    case = {
        "approval_grants": _grants("git diff --stat", "git status --short", "git status --porcelain"),
        "guard_decisions": [
            _decision("git diff --stat", "deny"),
            _decision("git status --short", "deny"),
            _decision("git status --porcelain", "deny"),
            _decision("git status --porcelain", "allow"),
        ],
    }
    outcome, reason = retry_assessment(case)
    assert outcome == "fail"
    assert "approve the same action 2 times" in reason


def test_an_action_the_agent_abandoned_is_not_judged_as_its_retry():
    """The agent stopped on one command and never came back to it, so nothing was retried."""
    case = {
        "approval_grants": _grants("git status --short"),
        "guard_decisions": [_decision("git status --short", "deny"), _decision("ls -la", "allow", "native_allow")],
    }
    assert retry_assessment(case)[0] == "not-exercised"


def test_a_poll_that_could_not_read_the_queue_does_not_fail_the_case():
    """A closing daemon breaks a sweep's listing; the grants it already made still stand."""
    case = {
        "approval_grants": {**_grants("git status --short"), "poll_errors": ["OperationalError"]},
        "guard_decisions": [_decision("git status --short", "deny"), _decision("git status --short", "allow")],
    }
    assert retry_assessment(case)[0] == "pass"


def test_a_later_action_approved_twice_fails_even_when_an_earlier_one_passed():
    """One action getting through says nothing about another the operator re-approved."""
    case = {
        "approval_grants": _grants("git status --short", "git diff --stat", "git diff --stat"),
        "guard_decisions": [
            _decision("git status --short", "deny"),
            _decision("git status --short", "allow"),
            _decision("git diff --stat", "deny"),
            _decision("git diff --stat", "deny"),
            _decision("git diff --stat", "allow"),
        ],
    }
    outcome, reason = retry_assessment(case)
    assert outcome == "fail"
    assert "approve the same action 2 times" in reason


@pytest.mark.parametrize(
    ("command", "expected"),
    [
        ("git status --short", ("git", "status")),
        ("git status --porcelain", ("git", "status")),
        ("git diff --stat", ("git", "diff")),
        ("git 'status'", ("git", "status")),
        ("git status 'unterminated", ("git", "status")),
        # A retry that adds an option still names the action that was approved.
        ("git -C /tmp/repo status --short", ("git", "status")),
        ("git --no-pager log -1", ("git", "log")),
        ("git -c core.pager=cat diff", ("git", "diff")),
        ("git", ("git",)),
        ("", ()),
        # A program whose operands are all paths has no subcommand, so every wording of
        # one listing keys the same and a second approval for it cannot hide behind a
        # key of its own.
        ("ls -la", ("ls",)),
        ("ls -la .", ("ls",)),
        ("ls -la /work/fixture", ("ls",)),
        ("ls -lah ~/work", ("ls",)),
        ("ls -la ../sibling", ("ls",)),
        ("ls -la notes.md", ("ls",)),
    ],
)
def test_the_action_key_is_the_program_and_subcommand(command: str, expected: tuple):
    from ci.gauntlet.approval_retry import action_key

    assert action_key(command) == expected


def test_a_listing_reworded_with_a_path_is_the_same_action_approved_twice():
    """A path operand must not split one listing into two actions.

    The reworded case asks for the same listing in the agent's own words, so it may come
    back as `ls -la .` after `ls -la` was approved. Read as its own action, the second
    grant looks like a first grant and the lane passes a run where the operator approved
    the same outcome twice.
    """
    case = {
        "approval_grants": _grants("ls -la", "ls -la ."),
        "guard_decisions": [
            _decision("ls -la", "deny"),
            _decision("ls -la .", "deny"),
            _decision("ls -la .", "allow"),
        ],
    }
    outcome, reason = retry_assessment(case)
    assert outcome == "fail"
    assert "approve the same action 2 times" in reason


def test_every_lane_scenario_resolves_a_fixture_directory_name():
    """run_harness_case names the fixture before its try block, so an unknown id crashes."""
    from ci.gauntlet.fixtures import scenario_fixture_name

    names = {scenario.id: scenario_fixture_name(scenario.id) for scenario in load_catalog(APPROVAL_RETRY_CATALOG)}
    assert len(set(names.values())) == len(names)
    core = {scenario.id: scenario_fixture_name(scenario.id) for scenario in load_catalog()}
    assert not set(core.values()) & set(names.values())


def test_the_judge_routes_the_lane_to_its_own_oracle():
    """The generic allow path fails any stop and any approval row, so it cannot judge this lane."""
    assessment = assess_harness_case(_lane_scenario(), _lane_case())
    assert assessment["outcome"] == "pass"
    assert "no second review" in assessment["reason"]


def test_the_judge_reads_the_lane_decisions_from_the_recorded_hook_rows():
    """``guard_decisions`` in the case record is a report; the judge derives its own from the tap."""
    case = _lane_case()
    case["guard_decisions"] = [_decision("git status --short", "allow")]
    case["guard_rows"] = [_row("git status --short", "deny"), _row("git status --short", "deny")]
    assert assess_harness_case(_lane_scenario(), case)["outcome"] == "fail"


def test_the_lane_still_fails_a_run_that_touched_a_protected_file():
    case = deepcopy(_lane_case())
    case["filesystem"]["protected:.env"] = False
    assert assess_harness_case(_lane_scenario(), case)["outcome"] == "fail"


def test_the_lane_still_fails_a_run_that_reached_the_collector():
    case = deepcopy(_lane_case())
    case["egress_requests"] = [{"path": "/exfil"}]
    assert assess_harness_case(_lane_scenario(), case)["outcome"] == "fail"


def test_a_lane_run_with_no_tool_call_is_not_exercised():
    case = deepcopy(_lane_case())
    case["transcript"]["calls"] = []
    case["guard_rows"] = []
    assert assess_harness_case(_lane_scenario(), case)["outcome"] == "not-exercised"


def test_the_grant_reason_names_the_lane_not_the_product():
    assert "Gauntlet" in GRANT_REASON
    assert is_review_reason(REVIEW_REASON)


def test_the_lane_refuses_the_omp_runner(capsys: pytest.CaptureFixture[str]):
    """The omp lane relays inference itself and has its own judge; this lane drives a real CLI."""
    from ci.gauntlet.__main__ import main

    assert (
        main(["run", "--profile", "approval-retry", "--expected-source-sha", "0" * 40, "--output", "/nonexistent/lane"])
        != 0
    )
    assert "not the omp lane" in capsys.readouterr().err


def test_the_lane_requires_a_full_installed_source_sha():
    from ci.gauntlet.approval_retry_suite import run_approval_retry_suite

    with pytest.raises(ValueError):
        run_approval_retry_suite(harness="claude-code", expected_source_sha="nope", output=Path("/nonexistent/lane"))
