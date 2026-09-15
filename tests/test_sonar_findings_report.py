"""The Sonar report must expose incomplete discovery and include its triggering PR."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import Mock

import pytest

from scripts.ci import sonar_findings_report as report


@pytest.fixture
def report_directory(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("PULL_REQUEST_NUMBER", raising=False)
    monkeypatch.setattr(
        report, "sonar_snapshot", Mock(return_value={"issues": {"total": 0}, "gate": {"status": "OK"}})
    )
    return tmp_path / "sonar-findings-report"


@pytest.mark.parametrize("failure", [OSError("unavailable"), ValueError("invalid JSON")])
@pytest.mark.parametrize("endpoint", ["/api/project_branches/list", "/api/project_pull_requests/list", "/pulls"])
def test_discovery_failure_still_writes_metadata_and_main_snapshot(
    report_directory: Path, monkeypatch: pytest.MonkeyPatch, failure: Exception, endpoint: str
) -> None:
    def read(_service: str, path: str, **_parameters: object):
        if path.endswith(endpoint):
            raise failure
        return [] if path.endswith("/pulls") else {}

    monkeypatch.setattr(report, "read_json", read)
    report.main()

    metadata = json.loads((report_directory / "metadata.json").read_text())
    assert len(metadata["errors"]) == 1
    assert metadata["errors"][0]["error"] == str(failure)
    assert (report_directory / "main.json").is_file()


@pytest.mark.parametrize("current", ["2778", "002778"])
def test_triggering_pr_is_fetched_even_when_open_pr_discovery_fails(
    report_directory: Path, monkeypatch: pytest.MonkeyPatch, current: str
) -> None:
    monkeypatch.setenv("PULL_REQUEST_NUMBER", current)
    trigger = {"number": 2778, "head": {"sha": "a" * 40, "ref": "fix/ordinary"}}

    def read(_service: str, path: str, **_parameters: object):
        if path.endswith("/pulls"):
            raise OSError("list unavailable")
        if path.endswith("/pulls/2778"):
            return trigger
        if path.endswith("/check-runs"):
            return {"total_count": 0, "check_runs": []}
        return {}

    monkeypatch.setattr(report, "read_json", read)
    report.main()

    metadata = json.loads((report_directory / "metadata.json").read_text())
    assert metadata["pull_requests"]["2778"]["checks_complete"] is True
    assert metadata["pull_requests"]["2778"]["head"] == "a" * 40
    assert metadata["errors"][0]["scope"] == "pull-request-discovery"
    assert (report_directory / "pr-2778.json").is_file()


@pytest.mark.parametrize("current", ["2778", "002778"])
def test_triggering_pr_is_included_when_it_is_not_in_the_open_list(
    report_directory: Path, monkeypatch: pytest.MonkeyPatch, current: str
) -> None:
    monkeypatch.setenv("PULL_REQUEST_NUMBER", current)
    trigger = {"number": 2778, "head": {"sha": "a" * 40, "ref": "fix/ordinary"}}
    calls = []

    def read(_service: str, path: str, **parameters: object):
        calls.append((path, parameters))
        if path.endswith("/pulls"):
            return []
        if path.endswith("/pulls/2778"):
            return trigger
        if path.endswith("/check-runs"):
            return {"total_count": 0, "check_runs": []}
        return {}

    monkeypatch.setattr(report, "read_json", read)
    report.main()

    metadata = json.loads((report_directory / "metadata.json").read_text())
    assert metadata["errors"] == []
    assert metadata["pull_requests"]["2778"]["checks_complete"] is True
    assert any(path.endswith("/pulls/2778") for path, _ in calls)
    assert (report_directory / "pr-2778.json").is_file()


def test_checks_beyond_five_pages_are_not_silently_omitted(monkeypatch: pytest.MonkeyPatch) -> None:
    def read(_service: str, _path: str, **parameters: object):
        page = parameters["page"]
        if page < 6:
            return {"total_count": 501, "check_runs": [{"conclusion": "success"}] * 100}
        return {"total_count": 501, "check_runs": [{"conclusion": "failure"}]}

    monkeypatch.setattr(report, "read_json", read)
    checks = report.github_pages("/check-runs", "check_runs")

    assert len(checks) == 501
    assert checks[-1]["conclusion"] == "failure"


@pytest.mark.parametrize("empty", [False, True])
def test_incomplete_checks_are_explicit_and_do_not_hide_the_snapshot(
    report_directory: Path, monkeypatch: pytest.MonkeyPatch, empty: bool
) -> None:
    pull = {"number": 2778, "head": {"sha": "a" * 40, "ref": "fix/sonar"}}

    def read(_service: str, path: str, **_parameters: object):
        if path.endswith("/pulls"):
            return [pull]
        if path.endswith("/check-runs"):
            return {"total_count": 2001, "check_runs": [] if empty else [{}] * 100}
        return {}

    monkeypatch.setattr(report, "read_json", read)
    report.main()

    metadata = json.loads((report_directory / "metadata.json").read_text())
    assert metadata["pull_requests"]["2778"]["checks_complete"] is False
    assert metadata["errors"][0]["scope"] == "pr-2778-checks"
    assert "incomplete" in metadata["errors"][0]["error"]
    assert (report_directory / "pr-2778.json").is_file()


def test_open_pr_pagination_does_not_stop_after_first_page(monkeypatch: pytest.MonkeyPatch) -> None:
    reader = Mock(side_effect=[[{"number": number} for number in range(100)], [{"number": 2778}]])
    monkeypatch.setattr(report, "read_json", reader)

    pulls = report.github_pages("/pulls")

    assert len(pulls) == 101
    assert pulls[-1] == {"number": 2778}
    assert reader.call_count == 2
