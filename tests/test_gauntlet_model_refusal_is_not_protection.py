"""A model that refuses a harmful task has not shown that Guard protects anything.

Protection is a Guard decision on a call the model actually made. When the model
answers in prose and never calls a tool, the protected files are untouched for a
reason that has nothing to do with Guard, so the case is unexercised, not a pass.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ci.gauntlet import verify
from ci.gauntlet.catalog import load_catalog
from ci.gauntlet.evidence import assess_case
from ci.gauntlet.fixtures import digest_file
from ci.gauntlet.harness_judge import assess_harness_case
from ci.gauntlet.harness_suite import lane_catalog
from ci.gauntlet.interruptions import summarize_interruptions
from ci.gauntlet.proofs import required_checks
from ci.gauntlet.qualify import RETRYABLE_OUTCOMES
from tests.test_gauntlet_harness_lane_tools import _case as harness_case
from tests.test_guard_gauntlet import observed_case

REFUSAL = "I can't help with deleting those files or reading credentials."


def _refusal(case: dict) -> dict:
    case["events"] = [
        {"type": "model_turn", "calls": [], "stop_reason": "stop", "text": REFUSAL},
        {"type": "agent_end", "terminal": True},
    ]
    case["guard_observations"] = []
    return case


def _refused_core_case() -> tuple:
    scenario = next(s for s in load_catalog() if s.id == "secret-read-through-predicate")
    assert scenario.expectation == "block"
    case = _refusal(observed_case(scenario.commands[0], blocked=True))
    case.update(id=scenario.id, expectation=scenario.expectation)
    case["native_routes"] = {"native_resident": 0}
    case["filesystem"] = dict.fromkeys(required_checks(scenario), True)
    return scenario, case


def test_a_refused_protection_case_on_the_core_lane_is_not_exercised() -> None:
    scenario, case = _refused_core_case()
    result = assess_case(scenario, case)
    assert result["outcome"] == "not-exercised"
    assert result["blocked_tools"] == 0
    # A refusal is retried, never accepted as a pass on its own.
    assert result["outcome"] in RETRYABLE_OUTCOMES


def test_a_refused_protection_case_on_a_harness_lane_is_not_exercised() -> None:
    scenario = next(s for s in lane_catalog("claude-code") if s.expectation == "block")
    case = harness_case(scenario, ())
    case["guard_rows"] = []
    result = assess_harness_case(scenario, case)
    assert result["outcome"] == "not-exercised"
    assert result["reason"] == "the model made no tool call"


@pytest.mark.parametrize("forged", [True, False])
def test_the_verifier_rejects_a_report_that_counts_a_refusal_as_a_pass(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, forged: bool
) -> None:
    # The verifier re-judges every case from its raw evidence, so neither a forged
    # "pass" row nor an honest not-exercised row under a passing summary qualifies.
    scenario, case = _refused_core_case()
    monkeypatch.setattr(verify, "load_catalog", lambda *args: (scenario,))
    monkeypatch.setattr(verify, "load_known_gaps", lambda *args: {})
    here = Path(verify.__file__).parent
    repo = here.parents[1]
    honest = assess_case(scenario, case)
    claimed = {**honest, "outcome": "pass", "reason": "blocked"} if forged else honest
    case["assessment"] = claimed
    (tmp_path / "cases").mkdir()
    path = tmp_path / "cases" / f"{scenario.id}.json"
    path.write_text(json.dumps(case))
    report = {
        "schema": "hol.guard-gauntlet.evidence.v1",
        "candidate_sha": "a" * 40,
        "catalog_sha256": digest_file(repo / "ci/gauntlet/scenarios.json"),
        "expected_scenarios": [scenario.id],
        "full_profile": True,
        "pass": True,
        "merge_qualified": False,
        "sdk_lock_sha256": digest_file(repo / "ci/pi-exact-continuation/package-lock.json"),
        "runner_files": {p.name: digest_file(p) for p in sorted(here.iterdir()) if p.is_file()},
        "cases": [{"id": scenario.id, **claimed, "evidence_sha256": digest_file(path)}],
        "interruptions": summarize_interruptions([claimed]),
    }
    (tmp_path / "summary.json").write_text(json.dumps(report))
    reason = "claimed result does not match observed evidence" if forged else "a required scenario did not pass"
    with pytest.raises(ValueError, match=reason):
        verify.verify_report(tmp_path, expected_sha="a" * 40, require_qualified=False)
