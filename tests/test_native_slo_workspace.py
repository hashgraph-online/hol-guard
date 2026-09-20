"""Finite collector accounting and failure controls; no native qualification doubles."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from scripts import native_slo_workspace as collector
from scripts.native_slo_failure import FixtureFailureError
from scripts.native_slo_workspace_observer import MAX_EVENTS
from scripts.native_slo_workspace_trace import event_digest


def _install(
    monkeypatch, *, fail_phase=None, startup_failure=False, bad_digest=False, wrong_runtime=False, cache_failed=False
):
    calls = []
    rows = [
        {
            "kind": "compile",
            "phase": 0,
            "publication": 1,
            "succeeded": True,
            "started_ms": 0,
            "finished_ms": 1,
            "thread_cpu_ms": 0.2,
        }
    ]
    observation = {
        "events": len(rows),
        "event_bound": MAX_EVENTS,
        "complete": True,
        "event_digest": "0" * 64 if bad_digest else event_digest(rows),
    }

    class Fixture:
        startup_ms, readiness_ms, pid = 10, 20, 123

        def __init__(self, runtime, *, policy, workspace_count):
            assert runtime == Path("runtime") and policy == "normal"
            self.count, self.index = workspace_count, 0
            calls.append((workspace_count, "created"))

        def __enter__(self):
            if startup_failure:
                raise FixtureFailureError(
                    {
                        "reason": "workspace_startup_failed",
                        "workspace_observation": {
                            "passed": False,
                            "observer": observation,
                            "retained_initial_pages": {"page_0": rows},
                        },
                    }
                )
            return self

        def __exit__(self, *_args):
            calls.append((self.count, "contained"))

        def control(self, operation, **arguments):
            calls.append((self.count, operation))
            if operation == "workspace_start":
                assert arguments == {"receipt_profile": "candidate"}
            if operation == "workspace_phase":
                assert arguments["phase"] == collector.WORKSPACE_PHASES[self.index]
                self.index += 1
                return {
                    "status": "completed",
                    "phase": arguments["phase"],
                    "passed": arguments["phase"] != fail_phase,
                    "binding": {
                        "generation": 7,
                        "policy_digest": "a" * 64,
                        "runtime_identity": ("c" if wrong_runtime else "b") * 64,
                    },
                }
            if operation == "workspace_finish":
                return {
                    "status": "completed",
                    "passed": fail_phase is None,
                    "observer": observation,
                    "cache_feature_checks_passed": not cache_failed,
                }
            if operation == "workspace_page":
                assert arguments == {"offset": 0}
                return {"status": "completed", "rows": rows, "total": len(rows)}
            return {"status": "completed"}

    class Resources:
        def __init__(self, *, pid):
            assert pid == 123

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            calls.append((0, "resources_stopped"))

        def report(self, *, attempted):
            return {"attempted": attempted, "samples": 2, "sample_minimum_met": False}

    monkeypatch.setattr(collector, "_clear_proof_overrides", lambda: calls.append((0, "cleared")))
    monkeypatch.setattr(
        collector, "_runtime_summary", lambda runtime: {"build_sha": "f" * 40, "runtime_sha256": "b" * 64}
    )
    monkeypatch.setattr(collector, "DaemonFixture", Fixture)
    monkeypatch.setattr(collector, "ResourceSampler", Resources)
    return calls


def test_three_independent_counts_keep_every_offer_terminal_and_event_private(tmp_path, monkeypatch):
    calls = _install(monkeypatch)
    path = tmp_path / "events.jsonl"
    result = collector.run_workspace_sweep(Path("runtime"), raw_file=path)
    assert result["implemented_checks_passed"] and result["declared_matrix_visited"]
    assert result["headline_timing_eligible"] is result["full_rsp_128_129_qualification"] is False
    assert [cell["registered_workspaces"] for cell in result["cells"]] == [1, 10, 100]
    assert all(cell["fixture_contained"] and cell["unvisited_phases"] == [] for cell in result["cells"])
    assert calls[0] == (0, "cleared")
    rows = [json.loads(line) for line in path.read_text().splitlines()]
    assert sum(row["kind"] == "control_offer" for row in rows) == 27
    assert sum(row["kind"] == "control_terminal" for row in rows) == 27
    assert sum(row["kind"] == "publisher_event" for row in rows) == 3
    assert result["ledger"]["records"] == len(rows)
    if os.name != "nt":
        assert path.stat().st_mode & 0o777 == 0o600
    with pytest.raises(FileExistsError):
        collector.run_workspace_sweep(Path("runtime"), raw_file=path)


def test_failed_phase_is_retained_and_suffix_stays_unvisited_for_each_count(tmp_path, monkeypatch):
    _install(monkeypatch, fail_phase="stricter_overlay")
    result = collector.run_workspace_sweep(Path("runtime"), raw_file=tmp_path / "failed.jsonl")
    assert not result["implemented_checks_passed"] and result["declared_matrix_visited"]
    for cell in result["cells"]:
        assert cell["fixture_contained"] and not cell["passed"]
        assert len(cell["phases"]) == 3 and cell["phases"][-1]["passed"] is False
        assert cell["unvisited_phases"] == list(collector.WORKSPACE_PHASES[3:])
        assert cell["retained_events"] == 1


def test_startup_failure_keeps_bounded_initial_spans_and_no_invented_phase_attempt(tmp_path, monkeypatch):
    _install(monkeypatch, startup_failure=True)
    path = tmp_path / "startup-failed.jsonl"
    result = collector.run_workspace_sweep(Path("runtime"), raw_file=path)
    assert not result["implemented_checks_passed"]
    for cell in result["cells"]:
        assert cell["retained_startup_events"] == 1 and cell["phases"] == []
        assert cell["unvisited_phases"] == list(collector.WORKSPACE_PHASES)
    records = [json.loads(line) for line in path.read_text().splitlines()]
    assert len([row for row in records if row["kind"] == "publisher_event"]) == 3
    assert not any(row["kind"] == "control_offer" for row in records)


def test_event_digest_mismatch_preserves_final_controls_but_fails_the_cell(tmp_path, monkeypatch):
    _install(monkeypatch, bad_digest=True)
    result = collector.run_workspace_sweep(Path("runtime"), raw_file=tmp_path / "wrong-digest.jsonl")
    assert not result["implemented_checks_passed"]
    assert all(not cell["passed"] and cell["final"]["passed"] for cell in result["cells"])


def test_malformed_startup_trace_fails_without_writing_an_unbounded_failure_record(tmp_path, monkeypatch):
    _install(monkeypatch, startup_failure=True, bad_digest=True)
    result = collector.run_workspace_sweep(Path("runtime"), raw_file=tmp_path / "bad-startup.jsonl")
    assert not result["implemented_checks_passed"] and result["declared_matrix_visited"]
    assert all(cell["failure"]["startup_trace_retained"] is False for cell in result["cells"])


def test_other_native_binary_cannot_pass_even_when_server_and_transport_report_success(tmp_path, monkeypatch):
    _install(monkeypatch, wrong_runtime=True)
    result = collector.run_workspace_sweep(Path("runtime"), raw_file=tmp_path / "wrong-runtime.jsonl")
    assert not result["implemented_checks_passed"]
    for cell in result["cells"]:
        assert not cell["passed"] and len(cell["phases"]) == 1
        assert cell["phases"][0]["installed_runtime_matches"] is False


def test_uncached_baseline_continues_authority_phases_but_cannot_pass_cache_feature_gate(tmp_path, monkeypatch):
    _install(monkeypatch, cache_failed=True)
    result = collector.run_workspace_sweep(Path("runtime"), raw_file=tmp_path / "uncached.jsonl")
    assert result["authority_checks_passed"] and not result["implemented_checks_passed"]
    assert all(len(cell["phases"]) == 6 and not cell["unvisited_phases"] for cell in result["cells"])


def test_direct_script_cli_help_works_without_pythonpath_or_source_package_injection():
    result = subprocess.run(
        [sys.executable, "scripts/native_slo_workspace.py", "--help"],
        cwd=Path(__file__).resolve().parents[1],
        env={key: value for key, value in os.environ.items() if key != "PYTHONPATH"},
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert "--ledger" in result.stdout and "--report" in result.stdout


@pytest.mark.parametrize("counts", [(), (True,), (2,), (100, 10), (1, 1), [1, 10, 100]])
def test_count_input_is_finite_and_canonical(tmp_path, counts):
    with pytest.raises(ValueError):
        collector.run_workspace_sweep(Path("runtime"), raw_file=tmp_path / "invalid.jsonl", counts=counts)
    assert not (tmp_path / "invalid.jsonl").exists()


def test_partial_count_run_cannot_pass_full_declared_matrix(tmp_path, monkeypatch):
    _install(monkeypatch)
    result = collector.run_workspace_sweep(Path("runtime"), raw_file=tmp_path / "one.jsonl", counts=(1,))
    assert result["cells"][0]["passed"]
    assert not result["implemented_checks_passed"] and not result["declared_matrix_visited"]


def test_legacy_receipt_profile_requires_exact_original_native_build_before_any_cell(tmp_path, monkeypatch):
    calls = _install(monkeypatch)
    with pytest.raises(ValueError):
        collector.run_workspace_sweep(
            Path("runtime"), raw_file=tmp_path / "wrong-baseline.jsonl", receipt_profile="baseline_2e672d2"
        )
    assert calls == [(0, "cleared")]
    assert not (tmp_path / "wrong-baseline.jsonl").exists()
