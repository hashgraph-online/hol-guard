"""Keep per-change security proof complete without running an extended soak each time."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest
import yaml

from scripts.ci.sonar_findings_report import _metric_value

ROOT = Path(__file__).resolve().parents[1]
SOAK = (
    "tests/test_guard_cloud_review_runtime_recovery.py::"
    "test_cloud_review_worker_survives_ten_thousand_recurring_disconnects"
)


def test_extended_soak_is_scheduled_while_routine_recovery_still_runs() -> None:
    action = yaml.safe_load((ROOT / ".github/actions/ci-job-scheduling-sensitive/action.yml").read_text())
    steps = action["runs"]["steps"]
    normal = next(step for step in steps if step.get("name") == "Run scheduling-sensitive tests untraced")
    extended = next(step for step in steps if step.get("name") == "Run extended reconnect soak without tracing")
    assert SOAK not in normal["run"] and "if" not in normal
    assert extended["if"] == "github.event_name == 'schedule' || github.event_name == 'workflow_dispatch'"
    assert SOAK in extended["run"]
    assert "--cov" not in normal["run"] and "--cov" not in extended["run"]
    assert "continue-on-error" not in normal and "continue-on-error" not in extended
    tests = ast.parse((ROOT / "tests/test_guard_cloud_review_runtime_recovery.py").read_text())
    functions = {node.name: node for node in tests.body if isinstance(node, ast.FunctionDef)}
    for name, count in (
        ("test_cloud_review_worker_recovers_from_recurring_disconnects", 300),
        ("test_cloud_review_worker_survives_ten_thousand_recurring_disconnects", 10_000),
    ):
        assert any(
            isinstance(node, ast.keyword)
            and node.arg == "iterations"
            and isinstance(node.value, ast.Constant)
            and node.value.value == count
            for node in ast.walk(functions[name])
        )
    ci = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())
    events = ci.get("on", ci.get(True))
    assert "schedule" in events and "workflow_dispatch" in events
    assert "scheduling-sensitive" in ci["jobs"]["ci-python-312"]["needs"]
    assert SOAK in ci["jobs"]["coverage"]["steps"][-1].get("run", "") or any(
        SOAK in step.get("run", "") for step in ci["jobs"]["coverage"]["steps"]
    )


def test_exact_analysis_gate_and_evidence_remain_in_the_scanned_job() -> None:
    action = yaml.safe_load((ROOT / ".github/actions/ci-job-sonar/action.yml").read_text())
    steps = action["runs"]["steps"]
    scan = next(i for i, step in enumerate(steps) if step.get("name") == "Analyze with SonarQube Cloud")
    index = next(i for i, step in enumerate(steps) if step.get("name") == "SonarQube Quality Gate check")
    gate = steps[index]
    assert scan < index and "continue-on-error" not in gate
    assert gate["run"] == "timeout --signal=TERM --kill-after=5s 300s python -m scripts.ci.check_sonar_quality"
    assert gate["if"] == (
        "inputs.has-token == 'true' && github.event_name == 'push' && github.ref == 'refs/heads/main'"
    )
    vendor = next(step for step in steps if step.get("name") == "Check standard Sonar gate for PRs and qualification")
    assert vendor["uses"] == "sonarsource/sonarqube-quality-gate-action@7a5fffe8e523c40e0c740b6bc2712ab503e52efa"
    assert vendor["if"] == (
        "inputs.has-token == 'true' && !(github.event_name == 'push' && github.ref == 'refs/heads/main')"
    )
    assert vendor["with"]["pollingTimeoutSec"] == 280
    assert "continue-on-error" not in vendor

    assert gate["env"] == {"SONAR_TOKEN": "${{ inputs.secret-sonar-token }}"}
    evidence = next(step for step in steps if step.get("name") == "Preserve analysis-specific quality evidence")
    assert evidence["if"] == (
        "always() && inputs.has-token == 'true' && github.event_name == 'push' && github.ref == 'refs/heads/main'"
    )
    assert evidence["with"]["path"] == "sonar-quality-evidence/"
    properties = (ROOT / "sonar-project.properties").read_text()
    assert "sonar.coverage.exclusions" not in properties and "sonar.sources=src,rust" in properties


@pytest.mark.parametrize(
    ("metric", "expected"),
    [
        ({"periods": [{"index": 1, "value": "42"}]}, 42),
        ({"period": {"value": "7"}}, 7),
        ({"value": "3"}, 3),
        ({}, None),
        ({"periods": [{"index": 2, "value": "99"}, {"index": 1, "value": "42"}]}, 42),
        ({"periods": [{"index": 1, "value": None}]}, None),
        ({"periods": [{"index": 1}]}, None),
        ({"periods": [{"index": 2, "value": "99"}]}, None),
        ({"periods": [{"index": 1, "value": "5"}, {"index": 1, "value": "6"}]}, None),
        ({"periods": "invalid"}, None),
        ({"periods": [None]}, None),
        ({"periods": [{"index": True, "value": "42"}]}, None),
        ({"periods": [{"value": "42"}]}, 42),
        ({"periods": [], "period": {"value": "7"}}, 7),
        ({"periods": None, "value": "3"}, 3),
        ({"period": None}, None),
        ({"period": "invalid"}, None),
        ({"value": "NaN"}, None),
        ({"value": "Infinity"}, None),
        ({"value": -1}, None),
        ({"value": True}, None),
    ],
)
def test_report_recognizes_all_supported_new_code_measurement_shapes(metric, expected):
    assert _metric_value(metric) == expected


@pytest.mark.parametrize("periods", [[{"index": 1}], [{"index": 1, "value": None}], "malformed"])
def test_unknown_gap_measurements_preserve_issues_and_request_source_evidence(monkeypatch, periods):
    from scripts.ci import sonar_findings_report as report

    component = {"key": "project:file", "measures": [{"metric": "new_uncovered_lines", "periods": periods}]}
    monkeypatch.setattr(
        report,
        "sonar_pages",
        lambda _path, field, **_kwargs: {field: [{"key": "issue"}] if field == "issues" else [component]},
    )
    calls = []

    def read(_service, path, **parameters):
        calls.append((path, parameters))
        return {"raw": "retained"}

    monkeypatch.setattr(report, "read_json", read)
    snapshot = report.sonar_snapshot(3532)
    assert snapshot["issues"]["issues"] == [{"key": "issue"}]
    assert snapshot["coverage"]["components"] == [component]
    assert snapshot["sources"]["project:file"] == {"raw": "retained"}
    assert any(path == "/api/sources/lines" and params["pullRequest"] == 3532 for path, params in calls)
