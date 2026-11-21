"""Main coverage reporting never waives security findings or contributor PR gates."""

from __future__ import annotations

import copy
import json
import os
import subprocess
from pathlib import Path
from unittest.mock import Mock

import pytest

from scripts.ci import check_sonar_quality as runner
from scripts.ci.sonar_quality_policy import REQUIRED_METRICS, conditions, number


def gate(coverage: str = "61.7") -> dict:
    entries = [
        ("new_reliability_rating", "1", "GT", "1"),
        ("new_security_rating", "1", "GT", "1"),
        ("new_maintainability_rating", "1", "GT", "1"),
        ("new_coverage", coverage, "LT", "80"),
        ("new_duplicated_lines_density", "1.1", "GT", "3"),
        ("new_security_hotspots_reviewed", "100", "LT", "100"),
    ]
    rows = []
    for metric, actual, comparator, threshold in entries:
        failed = number(actual) < number(threshold) if comparator == "LT" else number(actual) > number(threshold)
        rows.append(
            {
                "metricKey": metric,
                "actualValue": actual,
                "comparator": comparator,
                "errorThreshold": threshold,
                "periodIndex": 1,
                "status": "ERROR" if failed else "OK",
            }
        )
    return {
        "status": "ERROR" if any(row["status"] == "ERROR" for row in rows) else "OK",
        "conditions": rows,
        "periods": [{"index": 1, "mode": "previous_version", "date": "2026-09-04T13:19:40+0000"}],
        "ignoredConditions": False,
    }


def row(payload: dict, metric: str) -> dict:
    return next(item for item in payload["conditions"] if item["metricKey"] == metric)


def test_full_green_gate_remains_distinguishable_from_reported_debt():
    client = Mock()
    client.gate.return_value = gate("95")
    report = {}
    assert runner.evaluate(client, "analysis-id", {}, report)
    assert report["decision"] == "full-quality-gate-passed"
    assert report["sonar_status"] == "OK"


@pytest.mark.parametrize("metric", [*sorted(REQUIRED_METRICS), "future_security_metric"])
def test_every_noncoverage_failure_blocks(metric):
    payload = gate()
    if metric == "future_security_metric":
        payload["conditions"].append(
            {"metricKey": metric, "status": "ERROR", "actualValue": "1", "comparator": "GT", "errorThreshold": "0"}
        )
    else:
        item = row(payload, metric)
        item["actualValue"] = "0" if item["comparator"] == "LT" else "4"
        item["status"] = "ERROR"
    client = Mock()
    client.gate.return_value = payload
    report = {}
    assert not runner.evaluate(client, "analysis-id", {}, report)
    assert report["sonar_status"] == "ERROR"


@pytest.mark.parametrize(
    ("metric", "threshold"),
    [
        ("new_security_rating", "2"),
        ("new_reliability_rating", "2"),
        ("new_maintainability_rating", "2"),
        ("new_security_hotspots_reviewed", "90"),
        ("new_coverage", "60"),
        ("new_duplicated_lines_density", "4"),
    ],
)
def test_server_threshold_weakening_is_rejected(metric, threshold):
    payload = gate("95")
    row(payload, metric)["errorThreshold"] = threshold
    with pytest.raises(ValueError, match="weakened"):
        conditions(payload)


@pytest.mark.parametrize(
    "change", ["missing-security", "duplicate", "unknown-status", "inconsistent", "missing-actual", "nan"]
)
def test_incomplete_or_ambiguous_condition_evidence_fails_closed(change):
    payload = gate()
    if change == "missing-security":
        payload["conditions"].remove(row(payload, "new_security_rating"))
    elif change == "duplicate":
        payload["conditions"].append(copy.deepcopy(payload["conditions"][0]))
    elif change == "unknown-status":
        payload["status"] = "NONE"
    elif change == "inconsistent":
        payload["status"] = "OK"
    elif change == "missing-actual":
        row(payload, "new_coverage").pop("actualValue")
    else:
        row(payload, "new_coverage")["actualValue"] = "NaN"
    with pytest.raises(ValueError):
        conditions(payload)


@pytest.mark.parametrize("value", [None, 80, True, "NaN", "Infinity", "-Infinity", "invalid", "1" * 65])
def test_invalid_measurements_are_never_defaulted(value):
    with pytest.raises(ValueError):
        number(value)


@pytest.mark.parametrize("ignored", [True, None, "false"])
def test_green_main_analysis_must_explicitly_confirm_no_ignored_conditions(ignored):
    payload = gate("95")
    payload["ignoredConditions"] = ignored
    client = Mock()
    client.gate.return_value = payload
    with pytest.raises(ValueError, match="ignored gate conditions"):
        runner.evaluate(client, "analysis-id", {}, {})


def test_green_main_analysis_requires_explicit_coverage_evidence():
    payload = gate("95")
    payload["conditions"].remove(row(payload, "new_coverage"))
    client = Mock()
    client.gate.return_value = payload
    with pytest.raises(ValueError, match="omitted coverage evidence"):
        runner.evaluate(client, "analysis-id", {}, {})


@pytest.fixture
def main_push(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", os.devnull)

    def git(*args):
        return subprocess.check_output(["git", *args], text=True, timeout=10).strip()

    git("init", "-q", "-b", "main")
    git(
        "-c",
        "user.name=CI test",
        "-c",
        "user.email=ci@example.invalid",
        "-c",
        "commit.gpgsign=false",
        "commit",
        "--allow-empty",
        "-qm",
        "main test commit",
    )
    sha = git("rev-parse", "HEAD")
    event = {
        "ref": "refs/heads/main",
        "repository": {"full_name": runner.REPOSITORY},
        "after": sha,
        "forced": False,
        "deleted": False,
    }
    path = tmp_path / "event.json"
    path.write_text(json.dumps(event))
    environment = {
        "GITHUB_EVENT_NAME": "push",
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_SHA": sha,
        "GITHUB_REPOSITORY": runner.REPOSITORY,
        "GITHUB_EVENT_PATH": str(path),
    }
    return environment, event


@pytest.mark.parametrize("coverage", ["61.7", "79.9"])
def test_coverage_only_main_result_is_explicit_debt_not_a_false_green_or_ratchet(main_push, coverage):
    environment, _ = main_push
    client = Mock()
    client.gate.return_value = gate(coverage)
    report = {}
    assert runner.evaluate(client, "analysis-id", environment, report)
    assert report["decision"] == "main-coverage-debt-reported"
    assert report["sonar_status"] == "ERROR"
    runner.evidence(report, environment)
    saved = json.loads(Path("sonar-quality-evidence/quality.json").read_text())
    assert row(saved["gate"], "new_coverage")["actualValue"] == coverage
    assert saved["coverage_floor"] == "61.7"


@pytest.mark.parametrize("coverage", ["61.69", "50"])
def test_coverage_below_reviewed_anchor_remains_blocked(main_push, coverage):
    environment, _ = main_push
    client = Mock()
    client.gate.return_value = gate(coverage)
    report = {}
    assert not runner.evaluate(client, "analysis-id", environment, report)
    assert "decision" not in report


@pytest.mark.parametrize("change", ["pr", "release", "manual", "forced", "deleted", "foreign", "sha", "checkout"])
def test_coverage_policy_is_not_available_outside_the_exact_normal_main_push(main_push, change):
    environment, event = main_push
    if change == "pr":
        environment["GITHUB_EVENT_NAME"] = "pull_request"
    elif change == "release":
        environment["GITHUB_REF"] = "refs/heads/release/3.0"
    elif change == "manual":
        environment["GITHUB_EVENT_NAME"] = "workflow_dispatch"
    elif change in {"forced", "deleted"}:
        event[change] = True
    elif change == "foreign":
        environment["GITHUB_REPOSITORY"] = "another/repository"
    elif change == "sha":
        event["after"] = "0" * 40
    else:
        event["after"] = environment["GITHUB_SHA"] = "a" * 40
    with pytest.raises(ValueError):
        runner.verify_main_push(environment, event)


def test_missing_metadata_fails_with_preserved_evidence(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("SONAR_TOKEN", "test-only-token")
    monkeypatch.setattr(runner, "metadata_task", Mock(side_effect=OSError("metadata unavailable")))
    assert runner.main() == 1
    saved = json.loads(Path("sonar-quality-evidence/quality.json").read_text())
    assert saved["decision"] == "blocked" and "metadata unavailable" in saved["error"]


def test_recorded_public_main_analysis_matches_the_actual_gate_contract(main_push):
    fixture = Path(__file__).parent / "fixtures/sonar-main-quality-gate.v1.json"
    captured = json.loads(fixture.read_text(encoding="utf-8"))
    assert captured["project"] == "hashgraph-online_hol-guard"
    assert captured["projectStatus"]["ignoredConditions"] is False
    assert row(captured["projectStatus"], "new_coverage")["actualValue"] == "61.8"
    client = Mock()
    client.gate.return_value = captured["projectStatus"]
    report = {}
    assert runner.evaluate(client, captured["analysis_id"], main_push[0], report)
    assert report["decision"] == "main-coverage-debt-reported"
    assert report["sonar_status"] == "ERROR"
    assert report["gate"] == captured["projectStatus"]
