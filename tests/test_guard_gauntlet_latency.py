"""Latency evidence contracts; these tests do not qualify a live agent run."""

from __future__ import annotations

import pytest

from ci.gauntlet.input_evidence import public_observations
from ci.gauntlet.latency import summarize_hook_latency


def test_nearest_rank_and_event_distributions_include_tail_failures():
    rows = [{"elapsed_ms": n, "event": "PreToolUse", "http_status": 200} for n in range(1, 100)]
    rows.append({"elapsed_ms": 15000, "event": "SessionStart", "transport_error": True})
    result = summarize_hook_latency(rows)
    assert result["samples"] == 100
    assert [result[key] for key in ("p50_ms", "p90_ms", "p95_ms", "p99_ms", "max_ms")] == [50, 90, 95, 99, 15000]
    assert result["failed_attempts"] == 1
    assert result["mean_ms"] == 199.5
    assert result["by_event"]["SessionStart"]["p99_ms"] == 15000


@pytest.mark.parametrize("value", [None, True, "2", -1, float("nan"), float("inf")])
def test_invalid_or_missing_timings_are_not_zero(value):
    result = summarize_hook_latency([{"elapsed_ms": value, "http_status": 200}])
    assert result["samples"] == 0
    assert result["missing_samples"] == 1
    assert result["p99_ms"] is None


def test_transport_failure_survives_public_export():
    row = {"transport_error": True, "elapsed_ms": 1000}
    assert public_observations([row], {}) == [row]
    assert summarize_hook_latency([row])["failed_attempts"] == 1


def test_empty_and_single_sample_distributions():
    assert summarize_hook_latency([])["p50_ms"] is None
    result = summarize_hook_latency([{"elapsed_ms": 0, "http_status": 200}])
    assert result["samples"] == 1
    assert result["p99_ms"] == result["max_ms"] == 0


@pytest.mark.parametrize("reported", [False, True])
def test_verifier_labels_legacy_reports_without_claiming_latency(tmp_path, monkeypatch, reported):
    import json
    from pathlib import Path

    from ci.gauntlet import verify
    from ci.gauntlet.evidence import assess_case
    from ci.gauntlet.fixtures import digest_file
    from tests.test_guard_gauntlet import observed_case, ordinary

    scenario = ordinary()
    monkeypatch.setattr(verify, "load_catalog", lambda *args: (scenario,))
    here = Path(verify.__file__).parent
    repo = here.parents[1]
    case = observed_case()
    case.update(id=scenario.id, expectation=scenario.expectation)
    case["assessment"] = assess_case(scenario, case)
    if reported:
        case["hook_latency"] = summarize_hook_latency(case["guard_observations"])
    (tmp_path / "cases").mkdir()
    path = tmp_path / "cases" / "ordinary.json"
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
        "cases": [{"id": scenario.id, **case["assessment"], "evidence_sha256": digest_file(path)}],
    }
    if reported:
        report["hook_latency"] = case["hook_latency"]
    (tmp_path / "summary.json").write_text(json.dumps(report))
    result = verify.verify_report(tmp_path, expected_sha="a" * 40, require_qualified=False)
    assert result["verified"] is True
    assert result["hook_latency_reported"] is reported
    assert result["cases_missing_latency_report"] == ([] if reported else [scenario.id])
    if reported:
        report["hook_latency"]["p99_ms"] = 1
        (tmp_path / "summary.json").write_text(json.dumps(report))
        with pytest.raises(ValueError, match="aggregate hook latency"):
            verify.verify_report(tmp_path, expected_sha="a" * 40, require_qualified=False)
