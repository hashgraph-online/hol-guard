"""An installed SLO exception retains its actual failed work and exits nonzero."""

from __future__ import annotations

import hashlib
import json
import threading
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts import bench_guard_native_installed_slo as bench
from scripts import native_slo_launcher as launcher
from scripts import native_slo_session as sessions
from scripts.native_slo_adapter import Observation
from scripts.native_slo_failure import FixtureFailureError, failure_evidence
from scripts.native_slo_observation_failure import SloProgress
from scripts.native_slo_source_witness import source_review_witness


def _arguments(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    runtime = tmp_path / "native-fixture"
    runtime.write_bytes(b"fixture-only")
    destination = tmp_path / "slo.json"
    monkeypatch.setattr(
        bench.sys,
        "argv",
        ["slo", "--runtime", str(runtime), "--readiness-samples", "1", "--json", str(destination)],
    )
    return destination


def _pipeline(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, session: object) -> None:
    ordinary = Observation("pi", "PostToolUse", "1k", 1, "native_resident", True)
    monkeypatch.setattr(bench, "_clear_proof_overrides", lambda: None)
    monkeypatch.setattr(bench, "_runtime_summary", lambda _runtime: {"digest": "a" * 64})
    monkeypatch.setattr(bench, "route_matrix", lambda: (("pi", "PostToolUse"),))
    monkeypatch.setattr(bench, "_installed_corpus", lambda *_args: {})
    monkeypatch.setattr(bench, "AdapterSession", lambda _runtime: nullcontext(session))
    monkeypatch.setattr(bench, "_run_cold", lambda *_args: [1.0])
    monkeypatch.setattr(bench, "_run_warm", lambda *_args: [ordinary])
    monkeypatch.setattr(bench, "_run_recovery", lambda *_args: [1.0])
    capacity = SimpleNamespace(
        concurrent_16=[],
        concurrent_64=[],
        errors_16=0,
        errors_64=0,
        rss_baseline=1,
        rss_peak=1,
        routes_16={},
        routes_64={},
        native_overloads_16=0,
        native_overloads_64=0,
    )
    monkeypatch.setattr(bench, "measure_capacity", lambda *_args, **_kwargs: capacity)
    monkeypatch.setattr(bench, "process_rss_bytes", lambda: 1)


def test_main_retains_source_witness_verdict_routes_size_and_partial_phases(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    private_reason = "/home/private_marker/credentials unexpected ghp_fixture_material"
    count = 0

    def native(**kwargs):
        nonlocal count
        reference = kwargs["payload"]["guard_source_ref"]
        count += 1
        allowed = reference["output_chars"] == 250 * 1024
        return {
            "authority": "rust",
            "result": {
                "decision": "allow" if allowed else "deny",
                "policy_action": "allow" if allowed else "block",
                "model_output_action": "allow_original" if allowed else "block",
                "reason_code": "source_full_scan_allow" if allowed else private_reason,
                "reviewed_output_sha256": reference["output_sha256"] if allowed else None,
            },
        }

    worker = SimpleNamespace(
        _review_raw_hook_native=native,
        metrics=SimpleNamespace(snapshot=lambda: {"routes": {"native_resident": count}}),
    )
    session = sessions.AdapterSession.__new__(sessions.AdapterSession)
    session.workspace = session.root = session.guard_home = tmp_path
    session.runtime = tmp_path / "runtime"
    session._owner_thread_id = threading.get_ident()
    session._connection = None
    session.daemon = SimpleNamespace(_server=SimpleNamespace(hook_worker=worker))
    monkeypatch.setattr(
        sessions,
        "_request",
        lambda *_args, **kwargs: worker._review_raw_hook_native(payload=kwargs["request_payload"])["result"],
    )
    monkeypatch.setattr(bench, "source_reference_supported", lambda **_kwargs: True)
    _pipeline(tmp_path, monkeypatch, session)
    destination = _arguments(tmp_path, monkeypatch)
    assert bench.main() == 1  # Failure remains nonzero even without --enforce.
    report = json.loads(destination.read_text())
    assert json.loads(capsys.readouterr().out) == report
    assert report["passed"] is report["qualification_complete"] is False
    detail = report["failure"]
    assert detail["failed_phase"] == detail["sample_phase"] == "sizes"
    assert detail["stage"] == "reference_witness"
    assert detail["harness"] == "pi" and detail["event"] == "PostToolUse"
    assert detail["size_class"] == "1m" and detail["sample_index"] == 1
    assert detail["completed_sample_counts"] == {"cold": 1, "warm": 1, "sizes": 1}
    assert detail["completed_phases"] == ["runtime_identity", "installed_corpus", "cold", "cold_session", "warm"]
    assert detail["routes_before"]["native_resident"] == 1
    assert detail["routes_after"]["native_resident"] == 2
    assert detail["route"] == "native_resident"
    observed = detail["native_observations"][0]
    assert observed["rust_authority"] is True
    assert observed["reference_digest_matches"] is False
    assert observed["verdict"]["decision"] == "deny"
    assert observed["verdict"]["model_action"] == "block"
    digest = hashlib.sha256(json.dumps(private_reason, separators=(",", ":")).encode()).hexdigest()
    assert observed["verdict"]["reason_code_digest"] == digest
    assert detail["observed_semantics"]["delivered"]["reason_code_digest"] == digest
    assert detail["full_review_qualified"] is False
    serialized = json.dumps(report)
    assert "private_marker" not in serialized and "ghp_fixture_material" not in serialized
    assert "reason_code" not in observed["verdict"]


@pytest.mark.parametrize("failure", ["route", "exit", "json"])
def test_main_retains_launcher_failure_and_completed_preflight_samples(
    failure: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    counters = {"native_resident": 0, "native_fail_safe": 0}
    metrics = SimpleNamespace(snapshot=lambda: {"routes": dict(counters)})
    ordinary = Observation("pi", "PostToolUse", "1k", 1, "native_resident", True)
    session = SimpleNamespace(
        root=tmp_path,
        workspace=tmp_path,
        runtime=tmp_path / "runtime",
        guard_home=tmp_path,
        readiness_ms=1,
        daemon=SimpleNamespace(_server=SimpleNamespace(hook_worker=SimpleNamespace(metrics=metrics))),
        observe=lambda *_args: ordinary,
    )
    calls = 0
    private_reason = "unknown.private_marker.ghp_fixture_material"

    def run(*_args, **_kwargs):
        nonlocal calls
        calls += 1
        failed = calls == 4  # Two preflights and one timed call completed first.
        matching = calls == 2
        response = {
            "decision": "deny" if matching else "allow",
            "policy_action": "block" if matching else "allow",
            "model_output_action": "block" if matching else "allow_original",
            "reason_code": private_reason if failed else "output_secret_match" if matching else "output_scan_allow",
        }
        counters["native_fail_safe" if failed and failure == "route" else "native_resident"] += 1
        return SimpleNamespace(
            returncode=9 if failed and failure == "exit" else 0,
            timed_out=False,
            containment_failed=False,
            output_limit_exceeded=False,
            stdout="/home/private_marker malformed" if failed and failure == "json" else json.dumps(response),
            stderr="/home/private_marker private stderr",
        )

    _pipeline(tmp_path, monkeypatch, session)
    monkeypatch.setattr(bench, "_run_sizes", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(launcher.ClaudeCodeHarnessAdapter, "install", lambda *_args: None)
    monkeypatch.setattr(launcher, "registered_claude_argv", lambda *_args: ("registered-fixture",))
    monkeypatch.setattr(launcher, "run_isolated_hook_process", run)
    monkeypatch.setattr(launcher, "wait_for_route_corpus", lambda *_args, **_kwargs: metrics.snapshot())
    destination = _arguments(tmp_path, monkeypatch)
    assert bench.main() == 1
    report = json.loads(destination.read_text())
    assert json.loads(capsys.readouterr().out) == report
    detail = report["failure"]
    assert detail["failed_phase"] == "launcher"
    assert detail["sample_phase"] == "launcher_samples"
    assert detail["sample_index"] == 1 and detail["fixture_class"] == "benign"
    assert detail["harness"] == "claude-code" and detail["size_class"] == "1k"
    assert detail["completed_sample_counts"]["launcher_preflight"] == 2
    assert detail["completed_sample_counts"]["launcher"] == 1
    assert "capacity" in detail["completed_phases"] and "launcher" not in detail["completed_phases"]
    assert detail["routes_before"]["native_resident"] == 3
    assert detail["process"]["exit_code"] == (9 if failure == "exit" else 0)
    assert detail["stage"] == {"route": "route", "exit": "process", "json": "decode"}[failure]
    if failure == "route":
        assert detail["routes_after"]["native_fail_safe"] == 1
        assert detail["route"] == "native_fail_safe"
        assert detail["observed_semantics"]["delivered"]["decision"] == "allow"
        assert detail["observed_semantics"]["native"]["available"] is False
        assert len(detail["observed_semantics"]["delivered"]["reason_code_digest"]) == 64
    assert "private_marker" not in json.dumps(report)
    assert "ghp_fixture_material" not in json.dumps(report)


def test_generic_run_failure_is_always_saved_without_private_exception_text(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def fail(*_args, **_kwargs):
        raise OSError(13, "/home/private_marker/secret-data")

    monkeypatch.setattr(bench, "run_slo", fail)
    destination = _arguments(tmp_path, monkeypatch)
    assert bench.main() == 1
    report = json.loads(destination.read_text())
    assert json.loads(capsys.readouterr().out) == report
    assert report["failure"]["errno"] == 13
    assert "private_marker" not in json.dumps(report)


def test_progress_preserves_existing_failure_message_and_original_reason() -> None:
    progress = SloProgress()
    with progress.phase("first"):
        progress.counts["first"] = 2
    with (
        pytest.raises(FixtureFailureError, match="old caller-visible message") as caught,
        progress.phase("outer"),
        progress.phase("inner"),
    ):
        raise FixtureFailureError({"reason": "specific_failure"}, message="old caller-visible message")
    detail = failure_evidence(caught.value)
    assert detail["reason"] == "qualification_fixture.specific_failure"
    assert detail["failed_phase"] == "inner"
    assert detail["completed_phases"] == ["first"]
    assert detail["completed_sample_counts"] == {"first": 2}


@pytest.mark.parametrize("count", [0, 1, 2, 10])
def test_missing_native_verdict_is_unavailable_and_capture_is_bounded(count: int) -> None:
    worker = SimpleNamespace(_review_raw_hook_native=lambda **_kwargs: None)
    request = {"guard_source_ref": {"output_sha256": "a" * 64}}
    with pytest.raises(FixtureFailureError) as caught, source_review_witness(worker, request):
        for _ in range(count):
            worker._review_raw_hook_native()
    # Exercise the same outer failure envelope and privacy depth used by main.
    detail = bench.assert_privacy_safe({"failure": failure_evidence(caught.value)})["failure"]
    assert detail["observation_count"] == min(count, 2)
    assert detail["observation_count_is_lower_bound"] is (count >= 2)
    assert len(detail["native_observations"]) == min(count, 2)
    for observed in detail["native_observations"]:
        assert observed["verdict"] == {"available": False}
        assert observed["rust_authority"] is False
        assert observed["reference_digest_matches"] is False


@pytest.mark.parametrize(("passed", "enforce", "expected_exit"), [(True, True, 0), (False, True, 1), (False, False, 0)])
def test_successful_measurement_keeps_existing_gate_exit_behavior(
    passed: bool,
    enforce: bool,
    expected_exit: int,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    report = {"schema": "hol-guard.native-installed-slo.v1", "passed": passed}
    monkeypatch.setattr(bench, "run_slo", lambda *_args, **_kwargs: report)
    destination = _arguments(tmp_path, monkeypatch)
    if enforce:
        bench.sys.argv.append("--enforce")
    assert bench.main() == expected_exit
    assert json.loads(destination.read_text()) == json.loads(capsys.readouterr().out) == report
