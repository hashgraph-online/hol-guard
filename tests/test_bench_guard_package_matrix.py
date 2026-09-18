"""Benchmark qualification must observe full results and deterministic samples."""

from __future__ import annotations

import json
from copy import deepcopy
from itertools import pairwise

import pytest

from scripts.bench_guard_package_matrix import compare_results, observed_phase, resume_checkpoint, validate_arm_source


def _arm():
    return {
        "status": "complete",
        "measurement": {
            "source_commit": "commit",
            "source_diff_sha256": "diff",
            "corpus_sha256": "corpus",
            "semantic_sha256": ["partial"],
            "complete_result_sha256": ["full"],
            "persisted_evidence_sha256": ["evidence"],
            "wall_median_ms": 100,
            "cpu_median_ms": 90,
        },
    }


@pytest.mark.parametrize("field", ["corpus_sha256", "complete_result_sha256", "persisted_evidence_sha256"])
def test_matrix_rejects_full_result_or_evidence_difference_with_same_decision_subset(field: str) -> None:
    baseline = _arm()
    candidate = deepcopy(baseline)
    candidate["measurement"][field] = "different" if field == "corpus_sha256" else ["different"]
    assert compare_results(baseline, candidate)["status"] == "mismatch"


def test_matrix_rejects_identically_nondeterministic_sample_sets() -> None:
    baseline = _arm()
    baseline["measurement"]["complete_result_sha256"] = ["full", "changed"]
    assert compare_results(baseline, deepcopy(baseline))["status"] == "mismatch"


def test_matrix_never_treats_censored_timeout_as_latency() -> None:
    censored = {"status": "censored_whole_process_timeout", "whole_process_timeout_seconds": 20}
    assert compare_results(censored, _arm()) == {"status": "not_comparable"}


def test_failure_phase_distinguishes_primary_evaluation_from_additional_profile() -> None:
    primary = b'{"event":"measurement_started","sample":0}\n'
    profile = b'{"event":"profile_started","sample":1}\n'
    assert observed_phase(None) == "process_setup"
    assert observed_phase(primary) == "measurement_started"
    assert observed_phase(primary + profile + b'unrelated output\n{"event":"other"}\n') == "profile_started"


def test_matching_outputs_cannot_qualify_a_different_source() -> None:
    result = _arm()
    rejected = validate_arm_source(result, {"source_commit": "different", "source_diff_sha256": "diff"})
    assert rejected["status"] == "source_changed_during_collection"
    assert rejected["measurement"] == result["measurement"]
    assert compare_results(rejected, result) == {"status": "not_comparable"}


def test_matrix_compares_deterministic_different_sample_counts() -> None:
    baseline = _arm()
    candidate = deepcopy(baseline)
    for field in ("semantic_sha256", "complete_result_sha256", "persisted_evidence_sha256"):
        candidate["measurement"][field] *= 3
    candidate["measurement"]["cpu_median_ms"] = 45
    comparison = compare_results(baseline, candidate)
    assert comparison["status"] == "equal"
    assert comparison["median_cpu_improvement_percent"] == 50


def test_matrix_rejects_unequal_timed_sample_counts(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    import sys

    from scripts import bench_guard_package_matrix as runner

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "matrix",
            "--baseline-root",
            str(tmp_path),
            "--candidate-root",
            str(tmp_path),
            "--measurement-lock",
            str(tmp_path / "lock"),
            "--output",
            str(tmp_path / "report.json"),
            "--baseline-samples",
            "1",
            "--candidate-samples",
            "3",
        ],
    )
    with pytest.raises(SystemExit) as error:
        runner.main()
    assert error.value.code == 2


def test_matrix_order_changes_within_each_match_mode(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    import os
    import sys

    from scripts import bench_guard_package_matrix as runner

    if os.name != "posix":
        pytest.skip("The diagnostic runner requires POSIX advisory locking")
    observations = []

    def fake_arm(_args, **kwargs):
        observations.append((kwargs["mode"], kwargs["candidate"]))
        return _arm()

    monkeypatch.setattr(runner, "run_arm", fake_arm)
    monkeypatch.setattr(
        runner, "source_identity", lambda _root: {"source_commit": "commit", "source_diff_sha256": "diff"}
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "matrix",
            "--baseline-root",
            str(tmp_path),
            "--candidate-root",
            str(tmp_path),
            "--measurement-lock",
            str(tmp_path / "lock"),
            "--output",
            str(tmp_path / "report.json"),
        ],
    )
    assert runner.main() == 0
    first_arms = observations[::2]
    for mode in ("absent", "exact", "unversioned", "deny"):
        arm_orders = [candidate for observed_mode, candidate in first_arms if observed_mode == mode]
        assert len(arm_orders) == 9
        assert all(a != b for a, b in pairwise(arm_orders))


def _checkpoint() -> dict:
    return {
        "schema": "rsp-package-matrix-v2",
        "harness_sha256": "harness",
        "sources": {
            arm: {"source_commit": "commit", "source_diff_sha256": "diff"} for arm in ("baseline", "candidate")
        },
        "method": {
            "baseline_samples_per_cell": 1,
            "candidate_samples_per_cell": 1,
            "order": "alternating",
        },
        "matrix": [
            {
                "dependencies": 100,
                "bundle_records": 100,
                "mode": "absent",
                "baseline": _arm(),
                "candidate": _arm(),
                "comparison": compare_results(_arm(), _arm()),
            }
        ],
    }


@pytest.mark.parametrize("change", ["harness", "sample_count", "source", "historical_source", "prefix"])
def test_resume_rejects_incompatible_prior_observations(change: str, tmp_path) -> None:
    expected = _checkpoint()
    previous = deepcopy(expected)
    if change == "harness":
        previous["harness_sha256"] = "different"
    elif change == "sample_count":
        previous["method"]["candidate_samples_per_cell"] = 3
    elif change == "source":
        previous["sources"]["candidate"]["source_commit"] = "different"
    elif change == "historical_source":
        previous["matrix"][0]["baseline"]["measurement"]["source_commit"] = "different"
    else:
        previous["matrix"][0]["dependencies"] = 1000
    path = tmp_path / "checkpoint.json"
    path.write_text(json.dumps(previous))
    with pytest.raises(ValueError):
        resume_checkpoint(path, expected=expected, cases=[(100, 100, "absent")])


def test_resume_retains_failed_observation_and_collects_remaining_cells(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    import os
    import sys

    from scripts import bench_guard_package_matrix as runner

    if os.name != "posix":
        pytest.skip("The diagnostic runner requires POSIX advisory locking")
    observations = []

    def fake_arm(_args, **kwargs):
        observations.append((kwargs["dependencies"], kwargs["bundle_size"], kwargs["mode"]))
        return _arm()

    monkeypatch.setattr(runner, "run_arm", fake_arm)
    monkeypatch.setattr(
        runner, "source_identity", lambda _root: {"source_commit": "commit", "source_diff_sha256": "diff"}
    )
    path = tmp_path / "report.json"
    arguments = [
        "matrix",
        "--baseline-root",
        str(tmp_path),
        "--candidate-root",
        str(tmp_path),
        "--measurement-lock",
        str(tmp_path / "lock"),
        "--output",
        str(path),
    ]
    monkeypatch.setattr(sys, "argv", arguments)
    assert runner.main() == 0
    previous = json.loads(path.read_text())
    previous["matrix"] = previous["matrix"][:1]
    failed = previous["matrix"][0]
    failed["baseline"] = {"status": "censored_whole_process_timeout", "whole_process_timeout_seconds": 120}
    failed["comparison"] = {"status": "not_comparable"}
    path.write_text(json.dumps(previous))
    observations.clear()
    monkeypatch.setattr(sys, "argv", [*arguments, "--resume"])
    assert runner.main() == 2
    resumed = json.loads(path.read_text())
    assert resumed["matrix"][0] == failed
    assert len(resumed["matrix"]) == 36
    assert len(observations) == 70
    assert observations[0] == (100, 100, "exact")
    assert observations[-1] == (10000, 10000, "deny")
    assert resumed["collection_segments"][-1]["profile_enabled"] is False


def test_source_change_after_last_measurement_prevents_final_success(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    import os
    import sys

    from scripts import bench_guard_package_matrix as runner

    if os.name != "posix":
        pytest.skip("The diagnostic runner requires POSIX advisory locking")
    current = {"source_commit": "commit", "source_diff_sha256": "diff"}
    calls = 0

    def fake_arm(_args, **_kwargs):
        nonlocal calls
        calls += 1
        result = _arm()
        if calls == 72:
            current["source_commit"] = "changed-after-measurement"
        return result

    monkeypatch.setattr(runner, "run_arm", fake_arm)
    monkeypatch.setattr(runner, "source_identity", lambda _root: dict(current))
    path = tmp_path / "report.json"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "matrix",
            "--baseline-root",
            str(tmp_path),
            "--candidate-root",
            str(tmp_path),
            "--measurement-lock",
            str(tmp_path / "lock"),
            "--output",
            str(path),
        ],
    )
    assert runner.main() == 2
    report = json.loads(path.read_text())
    assert all(row["comparison"]["status"] == "equal" for row in report["matrix"])
    assert report["sources_unchanged_at_completion"] is False
