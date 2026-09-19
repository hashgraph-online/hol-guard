from __future__ import annotations

import json
import sys
from types import SimpleNamespace

import pytest

from scripts import bench_claude_native_launcher_pilot as probe
from scripts.native_slo_contract import assert_privacy_safe
from scripts.native_slo_failure import FixtureFailureError


def test_installed_setup_failure_retains_json_and_never_counts_measurements(tmp_path, monkeypatch):
    target = tmp_path / "failure.json"
    monkeypatch.setattr(sys, "argv", ["probe", "--wheel", str(tmp_path / "candidate.whl"), "--json", str(target)])

    def fail(*_args, **kwargs):
        kwargs["report"]["phase"] = "daemon_setup"
        raise RuntimeError("daemon fixture failed native startup")

    monkeypatch.setattr(probe, "run_probe", fail)
    assert probe.main() == 1
    result = json.loads(target.read_text())
    assert result["phase"] == "daemon_setup"
    assert result["cells"] == [] and result["completed_blocks"] == 0
    assert result["scope_complete"] is False and result["qualification_complete"] is False
    assert result["failure"]["reason"] == "daemon_fixture_failed_native_startup"
    assert result["missing_scopes"] and "comparison" not in result


def test_incomplete_or_missing_cpu_cannot_supply_improvement_gate():
    one = {
        "event": "PreToolUse",
        "arm": "python",
        "latency_ms": [100.0],
        "combined_cpu_complete": True,
        "cpu_ms_per_attempt": 10.0,
    }
    assert probe._comparison([one], blocks=1)["PreToolUse"] == {"complete": False}
    candidate = {
        **one,
        "arm": "native",
        "latency_ms": [10.0],
        "combined_cpu_complete": False,
        "cpu_ms_per_attempt": None,
    }
    result = probe._comparison([one, candidate], blocks=1)["PreToolUse"]
    assert result["latency_p95_ratio"] == 0.1
    assert result["cpu_mean_ratio"] is None and result["point_improvement_gate"] is False
    assert result["activation_qualified"] is False


def test_persisted_diagnostics_keep_missing_scopes_and_measured_numbers():
    report = {
        "missing_scopes": ["reference_review_faults", "watch_availability_faults"],
        "cells": [
            {
                "arm": "native",
                "event": "PreToolUse",
                "latency_ms": [3.0, 4.0],
                "combined_cpu_complete": True,
                "cpu_ms_per_attempt": 2.0,
            }
        ],
        "qualification_complete": False,
    }
    assert json.loads(json.dumps(assert_privacy_safe(report))) == report


def test_native_route_mismatch_never_returns_a_successful_series(monkeypatch):
    monkeypatch.setattr(probe, "_route_snapshot", lambda *_args, **_kwargs: {})
    monkeypatch.setattr(probe, "_children_cpu", lambda: 0.0)

    class Sampler:
        def __init__(self, **_kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            pass

        def report(self, **kwargs):
            return {"attempted": kwargs["attempted"], "samples": 1}

    monkeypatch.setattr(probe, "ResourceSampler", Sampler)
    monkeypatch.setattr(
        probe, "observe_priority_launcher", lambda *_args, **_kwargs: type("Observation", (), {"latency_ms": 1.0})()
    )
    controls = []
    session = SimpleNamespace(pid=123, control=lambda operation: controls.append(operation) or {})
    with pytest.raises(FixtureFailureError) as caught:
        probe._series(session, object(), 1)
    detail = caught.value.detail
    assert "native_route_mismatch" in detail["reason"]
    assert detail["excluded_from_comparison"] is True
    assert detail["attempted"] == detail["completed"] == 1
    assert detail["partial_daemon_resources"] == {"attempted": 1, "samples": 1}
    assert controls == ["case_before", "case_result"]
    assert "combined_cpu_complete" not in detail and "cpu_ms_per_attempt" not in detail


def test_preflight_refusal_retains_only_current_attempt_and_no_measurement(monkeypatch):
    controls = []
    evidence = {"native_call_count": 0, "native_completed_call_count": 0, "native_result": None}
    session = SimpleNamespace(control=lambda op: controls.append(op) or evidence)
    monkeypatch.setattr(probe, "_route_snapshot", lambda *_args, **_kwargs: {})

    def failed(*_args, **_kwargs):
        raise RuntimeError("priority_launcher_process_contract_failed")

    monkeypatch.setattr(probe, "observe_priority_launcher", failed)
    with pytest.raises(FixtureFailureError) as caught:
        probe._preflight(session, object(), case="benign")
    detail = caught.value.detail
    assert controls == ["case_before", "case_result"]
    assert detail["native_call_count"] == detail["native_completed_call_count"] == 0
    assert detail["last_native_semantics"] == {"available": False}
    assert detail["excluded_from_comparison"] is True
    assert "latency_ms" not in detail
