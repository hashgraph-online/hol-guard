"""Contracts for the approve-then-retry lane's catalog rules and judge predicate.

The judge tests exercise recorded case shapes, and focused integration tests cover the
lane-owned approval and authenticated-journal plumbing. Whether a real agent's retry
reuses an approval is answered only by running the lane against a harness CLI.
"""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path

import pytest

from ci.gauntlet.approval_retry import (
    CATALOG as APPROVAL_RETRY_CATALOG,
)
from ci.gauntlet.approval_retry import (
    GRANT_REASON,
    is_review_reason,
)
from ci.gauntlet.catalog import load_catalog
from ci.gauntlet.harness_judge import assess_harness_case
from tests.test_guard_gauntlet_approval_retry import REVIEW_REASON, _decision, _lane_case, _lane_scenario, _row


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


def test_the_omp_lane_still_requires_a_live_inference_provider(capsys: pytest.CaptureFixture[str]):
    """Adding consent support must not create a mock inference fallback."""
    from ci.gauntlet.__main__ import main

    assert (
        main(["run", "--profile", "approval-retry", "--expected-source-sha", "0" * 40, "--output", "/nonexistent/lane"])
        != 0
    )
    assert "live provider URL, model and provider identity are required" in capsys.readouterr().err


def test_the_lane_requires_a_full_installed_source_sha():
    from ci.gauntlet.approval_retry_suite import run_approval_retry_suite

    with pytest.raises(ValueError):
        run_approval_retry_suite(harness="claude-code", expected_source_sha="nope", output=Path("/nonexistent/lane"))
