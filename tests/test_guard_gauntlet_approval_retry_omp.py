"""OMP consent lane contracts; these synthetic judge inputs are not live qualification."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from ci.gauntlet import approval_retry_omp, runner
from ci.gauntlet.agent_prompt import fixture_authorization, scenario_prompt
from ci.gauntlet.approval_retry import CATALOG as APPROVAL_CATALOG
from ci.gauntlet.approval_retry_bash import ONCE_CASE
from ci.gauntlet.case_helpers import FIXTURE_SYSTEM_CONTEXT, fixture_system_context
from ci.gauntlet.catalog import catalog_digest, load_catalog
from ci.gauntlet.evidence import assess_case
from ci.gauntlet.fixtures import create_fixture
from tests.test_guard_gauntlet import observed_case, ordinary
from tests.test_guard_gauntlet_approval_retry import REVIEW_REASON
from tests.test_guard_gauntlet_bash_lifecycle import _LIFECYCLE_COMMAND, _lifecycle_case
from tests.test_guard_gauntlet_parallel import _fake_environment, _fake_result


def _scenario():
    return next(s for s in load_catalog(APPROVAL_CATALOG) if s.id == ONCE_CASE)


def _case():
    first = observed_case(_LIFECYCLE_COMMAND, blocked=True)
    first["guard_observations"][0]["reason_code"] = REVIEW_REASON
    retry = observed_case(_LIFECYCLE_COMMAND)
    for event in retry["events"]:
        if event.get("type") == "model_turn":
            event["calls"][0]["id"] = "c2"
        elif "toolCallId" in event:
            event["toolCallId"] = "c2"
    for row in retry["guard_observations"]:
        row["tool_call_id"] = "c2"
    first["events"] = first["events"][:-1] + retry["events"]
    first["guard_observations"] += retry["guard_observations"]
    first["native_routes"]["native_resident"] = 3
    first["approval_delta"] = 1
    first.update(_lifecycle_case(runs=1, persist=False, decisions=[]))
    return first


def test_consent_hooks_only_activate_for_the_dedicated_catalog():
    assert all(approval_retry_omp.enabled(s) for s in load_catalog(APPROVAL_CATALOG))
    assert not any(approval_retry_omp.enabled(s) for s in load_catalog())
    assert not approval_retry_omp.enabled(replace(_scenario(), profiles=("core", "approval-retry")))
    assert not approval_retry_omp.enabled(replace(_scenario(), oracle="commands"))
    with pytest.raises(ValueError, match="approval-retry"):
        approval_retry_omp.OmpReview(ordinary(), None, {})


def test_consent_prompt_allows_only_the_scenarios_bounded_retries(tmp_path: Path):
    fixture = create_fixture(tmp_path / "fixture")
    approval = _scenario()
    prompt = scenario_prompt(approval)
    context = fixture_authorization(fixture, "http://127.0.0.1:12345", approval)
    assert "Do not repeat any listed command" not in prompt
    assert "bounded retry instructions" in context
    assert "Never approve requests" in context
    assert "bounded retries" in fixture_system_context(approval)
    core = ordinary()
    assert "Do not repeat any listed command" in scenario_prompt(core)
    assert "A denial is the completed protection test" in fixture_authorization(fixture, "local", core)
    assert fixture_system_context(core) == FIXTURE_SYSTEM_CONTEXT


def test_omp_lane_uses_the_physical_bash_lifecycle_oracle():
    result = assess_case(_scenario(), _case())
    assert result["outcome"] == "pass", result
    case = _case()
    case["bash_lifecycle"]["report_runs"] = 0
    assert assess_case(_scenario(), case)["outcome"] == "fail"
    case = _case()
    case["bash_lifecycle"]["journal"] = []
    assert assess_case(_scenario(), case)["outcome"] == "fail"


@pytest.mark.parametrize("damage", ["host-input", "missing-post", "native-route", "terminal", "protected"])
def test_consent_oracle_cannot_bypass_shared_execution_proof(damage: str, monkeypatch):
    case = _case()
    if damage == "host-input":
        case["guard_observations"][1]["input"] = {"command": "echo substituted"}
    elif damage == "missing-post":
        case["guard_observations"].pop()
    elif damage == "native-route":
        case["native_routes"] = {}
    elif damage == "terminal":
        case["events"].pop()
    else:
        case["filesystem"]["protected:.env"] = False

    def forbidden(*_args):
        pytest.fail("consent oracle ran before shared host/native/physical validation")

    monkeypatch.setattr(approval_retry_omp, "assess", forbidden)
    assert assess_case(_scenario(), case)["outcome"] in {"harness-error", "false-negative"}


def test_core_still_rejects_a_review_even_if_the_tool_eventually_succeeded():
    case = observed_case()
    case["approval_delta"] = 1
    assert assess_case(ordinary(), case)["outcome"] == "false-positive"


@pytest.mark.parametrize("profile", ["core", "approval-retry"])
def test_deliberate_reviews_never_qualify_the_core_profile(monkeypatch, tmp_path: Path, profile: str):
    _fake_environment(monkeypatch)
    monkeypatch.setattr(runner, "run_case", lambda s, *, public, **_kw: _fake_result(s.id, public))
    monkeypatch.setattr(
        runner,
        "report_sections",
        lambda _cases: {"interruptions": {"benign_interruptions": 1}, "known_gaps": []},
    )
    # Keep markdown rendering separate from this report/qualification contract.
    monkeypatch.setattr(runner, "render_summary_markdown", lambda *_args: "unit report\n")
    report = runner.run_suite(expected_source_sha="a" * 40, output=tmp_path / "evidence", provider={}, profile=profile)
    assert report["profile"] == profile
    assert report["full_profile"] is True
    assert report["pass"] is (profile == "approval-retry")
    assert report["merge_qualified"] is False
    if profile == "approval-retry":
        assert report["catalog_sha256"] == catalog_digest(APPROVAL_CATALOG)
        assert {row["id"] for row in report["cases"]} == {s.id for s in load_catalog(APPROVAL_CATALOG)}


def test_a_quiet_all_pass_consent_report_still_cannot_be_merge_qualified(monkeypatch, tmp_path: Path):
    _fake_environment(monkeypatch)
    monkeypatch.setattr(runner, "run_case", lambda s, *, public, **_kw: _fake_result(s.id, public))
    report = runner.run_suite(
        expected_source_sha="a" * 40, output=tmp_path / "evidence", provider={}, profile="approval-retry"
    )
    assert report["pass"] is True
    assert report["merge_qualified"] is False


def test_approval_retry_rejects_parallel_jobs_before_starting_a_host(tmp_path: Path):
    with pytest.raises(ValueError, match="serially"):
        runner.run_suite(expected_source_sha="a" * 40, output=tmp_path, provider={}, profile="approval-retry", jobs=2)


def test_cli_routes_omp_consent_to_the_existing_session_runner(monkeypatch, tmp_path: Path):
    from ci.gauntlet.__main__ import main

    seen = {}

    def fake(**kwargs):
        seen.update(kwargs)
        return {"pass": True, "merge_qualified": False, "profile": "approval-retry", "cases": []}

    monkeypatch.setattr(runner, "run_suite", fake)
    assert (
        main(
            [
                "run",
                "--profile",
                "approval-retry",
                "--harness",
                "omp",
                "--expected-source-sha",
                "a" * 40,
                "--output",
                str(tmp_path),
                "--provider-url",
                "http://127.0.0.1:12345",
                "--allow-loopback-provider",
                "--model",
                "unit-routing-only",
                "--provider-identity",
                "unit-routing-only",
            ]
        )
        == 0
    )
    assert seen["profile"] == "approval-retry" and seen["jobs"] == 1
