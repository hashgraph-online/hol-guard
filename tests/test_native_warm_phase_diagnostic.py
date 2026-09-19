from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

from scripts import diagnose_guard_native_warm_phases as diagnostic


def test_same_request_phases_delegate_exact_objects_and_exclude_other_threads(monkeypatch):
    status_result = object()
    payload, result = object(), object()
    calls = []

    def status():
        calls.append("status")
        return status_result

    def transport(**kwargs):
        calls.append(kwargs)
        return result

    def adapter(request, **kwargs):
        assert request is payload and kwargs == {"observe_mode": False, "policy_snapshot": status_result}
        assert diagnostic.native_runtime.native_runtime_status() is status_result
        assert (
            cast(Any, diagnostic.native_runtime).native_resident_client_request(payload=request, deadline_monotonic=7)
            is result
        )
        worker = threading.Thread(target=diagnostic.native_runtime.native_runtime_status)
        worker.start()
        worker.join()
        return result

    monkeypatch.setattr(diagnostic.benchmark, "review_post_tool_native", adapter)
    monkeypatch.setattr(diagnostic.native_runtime, "native_runtime_status", status)
    monkeypatch.setattr(diagnostic.native_runtime, "native_resident_client_request", transport)
    observation = diagnostic.PhaseObservation()
    with observation.attached():
        assert (
            cast(Any, diagnostic.benchmark).review_post_tool_native(
                payload, observe_mode=False, policy_snapshot=status_result
            )
            is result
        )
    assert diagnostic.benchmark.review_post_tool_native is adapter
    assert diagnostic.native_runtime.native_runtime_status is status
    assert diagnostic.native_runtime.native_resident_client_request is transport
    assert calls == ["status", {"payload": payload, "deadline_monotonic": 7}, "status"]
    sample = observation.samples[0]
    assert {name: sample[name + "_calls"] for name in diagnostic._PHASES} == {"adapter": 1, "status": 1, "transport": 1}
    assert sample["adapter"] >= sample["status"] + sample["transport"] >= 0
    report = observation.report()
    assert report["scope"] == "separate_diagnostic_pass_not_acceptance"
    assert report["samples"] == 1
    assert set(report) == {"schema", "scope", "samples", "phases"}


def test_exception_identity_and_all_original_bindings_survive(monkeypatch):
    failure = RuntimeError("private-payload-canary")

    def adapter(*args, **kwargs):
        raise failure

    status = diagnostic.native_runtime.native_runtime_status
    transport = diagnostic.native_runtime.native_resident_client_request
    monkeypatch.setattr(diagnostic.benchmark, "review_post_tool_native", adapter)
    observation = diagnostic.PhaseObservation()
    with pytest.raises(RuntimeError) as caught, observation.attached():
        cast(Any, diagnostic.benchmark).review_post_tool_native(object())
    assert caught.value is failure
    assert diagnostic.benchmark.review_post_tool_native is adapter
    assert diagnostic.native_runtime.native_runtime_status is status
    assert diagnostic.native_runtime.native_resident_client_request is transport
    assert len(observation.samples) == 1 and observation.samples[0]["adapter_calls"] == 1
    assert "private" not in json.dumps(observation.report())


@pytest.mark.parametrize(
    "failure,reason", [(RuntimeError, "runtime_error"), (TimeoutError, "timeout_error"), (KeyError, "other")]
)
def test_cli_emits_only_finite_failure_without_traceback(tmp_path, monkeypatch, capsys, failure, reason):
    output = tmp_path / "diagnostic.json"
    monkeypatch.setattr(
        diagnostic, "diagnose", lambda *args: (_ for _ in ()).throw(failure("private-token-path-canary"))
    )
    monkeypatch.setattr(
        "sys.argv",
        ["diagnostic", "--runtime", "private-runtime-path-canary", "--warm-iterations", "30", "--json", str(output)],
    )
    assert diagnostic.main() == 1
    captured = capsys.readouterr()
    assert "private" not in captured.out + captured.err
    assert "Traceback" not in captured.out + captured.err
    result = json.loads(output.read_text())
    assert result == {
        "schema": "hol-guard-native-warm-phases.v1",
        "scope": "separate_diagnostic_pass_not_acceptance",
        "status": "failed",
        "reason": reason,
    }


def test_cli_artifact_failure_does_not_render_path(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(diagnostic, "diagnose", lambda *args: {"samples": 30})
    monkeypatch.setattr(
        "sys.argv",
        [
            "diagnostic",
            "--runtime",
            "synthetic",
            "--warm-iterations",
            "30",
            "--json",
            str(tmp_path / "private-path-canary" / "missing.json"),
        ],
    )
    assert diagnostic.main() == 1
    result = capsys.readouterr()
    assert "private" not in result.out + result.err and "Traceback" not in result.out + result.err
    assert json.loads(result.out)["reason"] == "artifact_write_failed"


@pytest.mark.parametrize("iterations", [30, 100])
def test_diagnostic_reuses_original_loop_and_restores_before_cleanup(monkeypatch, tmp_path, iterations):
    from contextlib import contextmanager

    events = []
    snapshot = {"generation": 1}
    original_adapter = diagnostic.benchmark.review_post_tool_native

    @contextmanager
    def snapshot_context(home):
        events.append("publish")
        yield snapshot
        assert diagnostic.benchmark.review_post_tool_native is original_adapter
        events.append("close-publisher")

    def status():
        return object()

    def transport(**kwargs):
        return b"synthetic"

    def review(*args, **kwargs):
        diagnostic.native_runtime.native_runtime_status()
        cast(Any, diagnostic.native_runtime).native_resident_client_request(payload=b"synthetic")
        return SimpleNamespace(decision="allow")

    def loop(**kwargs):
        assert kwargs["iterations"] == iterations and kwargs["policy_snapshot"] is snapshot
        events.append("original-loop")
        for _ in range(iterations):
            cast(Any, diagnostic.benchmark).review_post_tool_native(
                object(), policy_snapshot=snapshot, observe_mode=False
            )

    monkeypatch.setattr(diagnostic.benchmark, "review_post_tool_native", review)
    original_adapter = review
    monkeypatch.setattr(diagnostic.native_runtime, "native_runtime_status", status)
    monkeypatch.setattr(diagnostic.native_runtime, "native_resident_client_request", transport)
    monkeypatch.setattr(diagnostic.benchmark, "native_policy_snapshot", snapshot_context)
    monkeypatch.setattr(diagnostic.benchmark, "_validated_runtime", lambda path: path)
    monkeypatch.setattr(diagnostic.benchmark, "native_hook_route", lambda: "native_resident")
    monkeypatch.setattr(diagnostic.benchmark, "close_resident_native_runtimes", lambda: events.append("close-resident"))
    monkeypatch.setattr(diagnostic.benchmark, "_stop_native_resident", lambda *args: events.append("stop-resident"))
    monkeypatch.setattr(diagnostic.benchmark, "_bench_native_warm_production", loop)
    result = diagnostic.diagnose(tmp_path / "runtime", iterations)
    assert result["samples"] == iterations
    assert all(phase["calls"] == iterations for phase in cast(dict[str, dict[str, object]], result["phases"]).values())
    assert events == [
        "close-resident",
        "publish",
        "original-loop",
        "close-publisher",
        "stop-resident",
        "close-resident",
    ]


def test_unconfigured_sample_count_cannot_run(monkeypatch):
    monkeypatch.setattr(
        diagnostic.benchmark, "_validated_runtime", lambda path: pytest.fail("unexpected runtime access")
    )
    with pytest.raises(ValueError, match="sample count"):
        diagnostic.diagnose(Path("synthetic"), 31)


def test_actual_cli_startup_and_invalid_runtime_emit_finite_json(tmp_path):
    root = Path(__file__).resolve().parents[1]
    output = tmp_path / "report.json"
    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(root / "src")
    canary = "synthetic-private-runtime-82b49"
    result = subprocess.run(
        [
            sys.executable,
            str(root / "scripts/diagnose_guard_native_warm_phases.py"),
            "--runtime",
            str(tmp_path / canary),
            "--warm-iterations",
            "30",
            "--json",
            str(output),
        ],
        cwd=tmp_path,
        env=environment,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 1
    assert canary not in result.stdout + result.stderr
    assert "Traceback" not in result.stdout + result.stderr
    assert json.loads(output.read_text())["status"] == "failed"
