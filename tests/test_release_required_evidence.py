"""Contracts for required release collection, installed canaries, and negative outcomes."""

from __future__ import annotations

import copy
import hashlib
from pathlib import Path

import pytest

from scripts.ci.release_required_evidence import (
    REQUIRED_RELEASE_NODE_IDS,
    _contains_node,
    _installed_wheel_jobs,
    _workflow_jobs,
    build_report,
)
from scripts.ci.verify_release_negative_outcomes import (
    REQUIRED_TESTS,
    NegativeOutcomeError,
    result_digest,
    validate_negative_outcomes,
)

ROOT = Path(__file__).resolve().parents[1]


def _cases() -> list[dict[str, object]]:
    cases = [
        {"name": "draft", "result": "fail-closed", "passed": False, "evidence": "pytest-draft"},
        {"name": "wrong-workspace", "result": "refused", "passed": False, "evidence": "pytest-workspace"},
        {"name": "stale", "result": "fail-closed", "passed": False, "evidence": "pytest-stale"},
        {
            "name": "unavailable-runtime",
            "result": "unsupported",
            "passed": False,
            "evidence": "installed-matrix",
        },
        {"name": "immutable-block", "result": "refused", "passed": False, "evidence": "review-contract"},
    ]
    for case in cases:
        case["pytest_nodeid_sha256"] = hashlib.sha256(REQUIRED_TESTS[case["name"]].encode()).hexdigest()
    return cases


def _payload() -> dict[str, object]:
    source = "a" * 40
    execution = [
        {
            "nodeid_sha256": hashlib.sha256(node.encode()).hexdigest(),
            "setup": "passed",
            "call": "passed",
            "teardown": "passed",
        }
        for node in REQUIRED_TESTS.values()
    ]
    return {
        "schema": "hol-guard-release-negative-outcomes.v1",
        "source_sha": source,
        "cases": _cases(),
        "pytest_results": execution,
        "pytest_results_sha256": result_digest(source, execution),
    }


def test_release_required_tests_are_collected_and_not_silently_deselected() -> None:
    report = build_report(ROOT)

    assert report.missing_required == ()
    assert report.deselected_required == ()
    assert report.collected_release_cases >= len(REQUIRED_RELEASE_NODE_IDS)
    assert report.configured_canary_oses == ("ubuntu-latest", "macos-latest", "windows-latest")
    assert "publish-alpha-testpypi" in report.configured_wheel_jobs
    assert report.installed_runtime_verified is False
    assert report.evidence_kind == "collection-and-configuration"
    assert report.named_ci_deselects


def test_negative_outcomes_reject_happy_path_passes() -> None:
    payload = _payload()
    normalized = validate_negative_outcomes(payload)
    assert [case["name"] for case in normalized["cases"]] == [
        "draft",
        "wrong-workspace",
        "stale",
        "unavailable-runtime",
        "immutable-block",
    ]

    payload["cases"][0]["passed"] = True
    with pytest.raises(NegativeOutcomeError, match="must explicitly record"):
        validate_negative_outcomes(payload)


def test_negative_outcomes_require_every_named_fail_closed_case() -> None:
    payload = _payload()
    payload["cases"].pop()
    with pytest.raises(NegativeOutcomeError, match="incomplete"):
        validate_negative_outcomes(payload)


@pytest.mark.parametrize("value", [None, 0, 1, "false", "true", [], {}])
def test_negative_outcomes_require_literal_false(value: object) -> None:
    payload = _payload()
    payload["cases"][0]["passed"] = value
    with pytest.raises(NegativeOutcomeError, match="must explicitly record"):
        validate_negative_outcomes(payload)


def test_negative_outcomes_reject_missing_pass_field() -> None:
    payload = _payload()
    del payload["cases"][0]["passed"]
    with pytest.raises(NegativeOutcomeError, match="must explicitly record"):
        validate_negative_outcomes(payload)


@pytest.mark.parametrize("phase", ["setup", "call", "teardown"])
@pytest.mark.parametrize("outcome", ["skipped", "failed", None])
def test_negative_outcomes_reject_incomplete_execution(phase: str, outcome: object) -> None:
    payload = _payload()
    payload["pytest_results"][0][phase] = outcome
    payload["pytest_results_sha256"] = result_digest(payload["source_sha"], payload["pytest_results"])
    with pytest.raises(NegativeOutcomeError, match="did not execute"):
        validate_negative_outcomes(payload)


def test_negative_outcomes_require_matching_node_and_result_digests() -> None:
    for field in ("pytest_results_sha256", "pytest_nodeid_sha256"):
        payload = _payload()
        target = payload if field == "pytest_results_sha256" else payload["cases"][0]
        target[field] = "0" * 64
        with pytest.raises(NegativeOutcomeError, match="digest"):
            validate_negative_outcomes(payload)


def test_required_collection_rejects_similar_node_names() -> None:
    node = REQUIRED_RELEASE_NODE_IDS[0]
    assert _contains_node([node], node)
    assert _contains_node([node + "[case-1]"], node)
    assert not _contains_node(["other/" + node], node)
    assert not _contains_node([node + "_unrelated"], node)


@pytest.mark.parametrize("job", ["publish-alpha-testpypi", "publish-alpha-pypi", "publish-main-pypi"])
def test_each_publish_job_must_keep_its_own_wheel_check(job: str) -> None:
    jobs = copy.deepcopy(_workflow_jobs(ROOT))
    jobs[job]["steps"] = []
    with pytest.raises(RuntimeError, match="no configured wheel install"):
        _installed_wheel_jobs(jobs)
