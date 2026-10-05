from __future__ import annotations

import json
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from http.client import BadStatusLine, IncompleteRead
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.native_runtime import (
    NativeRuntimeCapabilities,
    NativeRuntimeIdentity,
    NativeRuntimeManifest,
    NativeRuntimeStatus,
)
from scripts import bench_guard_native_installed_slo as benchmark
from scripts import bench_guard_native_installed_slo_runtime as runtime_checks
from scripts import native_slo_capacity as capacity
from scripts.native_slo_adapter import Observation
from scripts.native_slo_progress import SloProgress, classify_benchmark_error, incomplete_slo_result
from scripts.native_slo_reporting import SloMeasurements, slo_result, summarize_measurements


def _report_measurements() -> SloMeasurements:
    observation = Observation("codex", "PreToolUse", "1k", 1.0, "native_resident", True)
    return SloMeasurements(
        warm=[observation],
        sizes=[],
        recovery=[12.0],
        cold=[1.0],
        concurrent_16=[observation] * 15,
        concurrent_64=[],
        errors_16=1,
        errors_64=0,
        readiness=[1.0],
        rss_baseline=1,
        rss_peak=1,
    )


def test_finished_run_keeps_failed_capacity_requests_in_denominators(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    def measure(*_args: object, progress: SloProgress, **_kwargs: object) -> SloMeasurements:
        progress.submit("concurrent_16", 16)
        progress.attempt("concurrent_16", 16)
        progress.complete("concurrent_16", 15)
        progress.fail_request("concurrent_16")
        return _report_measurements()

    monkeypatch.setattr(benchmark, "_clear_proof_overrides", lambda: None)
    monkeypatch.setattr(benchmark, "_runtime_summary", lambda _: {})
    monkeypatch.setattr(benchmark, "route_matrix", lambda: (("codex", "PreToolUse"),))
    monkeypatch.setattr(
        benchmark,
        "_installed_corpus",
        lambda *_: {
            "routes": 1,
            "resident": 1,
            "oneshot": 0,
            "fail_safe": 0,
            "python_semantic_decisions": 0,
        },
    )
    monkeypatch.setattr(benchmark, "_measure_slo", measure)
    result = benchmark.run_slo(
        tmp_path / "fixture-runtime",
        warm_iterations=1,
        cold_iterations=1,
        recovery_iterations=1,
        readiness_samples=1,
        include_capacity=True,
    )
    denominators = result["concurrency"]["sixteen"]["denominators"]
    assert denominators["planned"] == denominators["attempted"] == 16
    assert denominators["completed"] == 15
    assert denominators["failed"] == result["corpus"]["failed"] == 1
    assert denominators["missing"] == 0
    assert result["corpus"]["denominators"]["concurrent_16"] == denominators
    assert result["errors_16"] == 1
    assert result["gates"]["concurrency"] is False
    assert result["passed"] is False


@pytest.mark.parametrize("adapter_samples", [None, [], [2.0]])
def test_recovery_adapter_timing_requires_measured_adapter_samples(adapter_samples: list[float] | None) -> None:
    measurements = replace(_report_measurements(), recovery_adapter=adapter_samples)
    result = slo_result(
        {},
        (("codex", "PreToolUse"),),
        {},
        measurements,
        summarize_measurements(measurements),
        {"concurrency": False},
    )
    assert result["timing"]["recovery_enclosing"]["p95_ms"] == 12.0
    if adapter_samples:
        assert result["timing"]["recovery_adapter"]["p95_ms"] == 2.0
    else:
        assert result["timing"]["recovery_adapter"] is None


class _FixtureObject:
    def __init__(self, **fields: object) -> None:
        self.__dict__.update(fields)


def test_invocation_plan_keeps_route_dependent_work_unknown() -> None:
    progress = SloProgress()
    progress.configure_invocation(
        warm_iterations=2,
        cold_iterations=3,
        recovery_iterations=2,
        readiness_samples=2,
        include_capacity=True,
    )
    progress.activate("runtime")
    progress.record_failure(RuntimeError("fixture runtime unavailable"))

    result = incomplete_slo_result(progress, include_capacity=True)

    assert result["runtime"] is None
    assert result["routes"] is None
    assert result["corpus"]["planned"] is None
    assert result["corpus"]["denominators"]["cold"]["planned"] == 3
    assert result["corpus"]["denominators"]["warm"]["planned"] is None
    assert result["passed"] is False
    assert all(value is False for value in result["gates"].values())
    assert "fixture runtime unavailable" not in json.dumps(result)


def test_finished_cancelled_and_running_requests_have_distinct_counts() -> None:
    progress = SloProgress()
    progress.configure_invocation(
        warm_iterations=1,
        cold_iterations=1,
        recovery_iterations=1,
        readiness_samples=1,
        include_capacity=True,
    )
    progress.configure_routes((("codex", "PreToolUse"),))
    progress.submit("concurrent_16", 3)
    progress.attempt("concurrent_16", 2)
    progress.complete("concurrent_16")
    progress.cancel("concurrent_16")

    snapshot = progress.stage_snapshot()["concurrent_16"]
    assert snapshot["planned"] == 16
    assert snapshot["submitted"] == 3
    assert snapshot["attempted"] == 2
    assert snapshot["completed"] == 1
    assert snapshot["cancelled"] == 1
    assert snapshot["missing"] == 14


def test_typed_loopback_failure_precedes_status_wrapper() -> None:
    wrapped = RuntimeError("adapter request failed")
    wrapped.__cause__ = BadStatusLine("fixture status")

    assert classify_benchmark_error(wrapped) == "transport_error"
    for transport in (ConnectionResetError("fixture"), IncompleteRead(b"fixture", 20)):
        wrapped_transport = RuntimeError("adapter request failed")
        wrapped_transport.__cause__ = transport
        assert classify_benchmark_error(wrapped_transport) == "transport_error"
    for environment in (FileNotFoundError("fixture"), PermissionError("fixture")):
        wrapped_environment = RuntimeError("adapter request failed")
        wrapped_environment.__cause__ = environment
        assert classify_benchmark_error(wrapped_environment) == "environment_error"
    assert classify_benchmark_error(RuntimeError("adapter request failed")) == "response_status"
    assert classify_benchmark_error(TimeoutError("fixture timeout")) == "transport_timeout"
    assert classify_benchmark_error(RuntimeError("concurrent capacity wave timed out")) == "capacity_wave_timeout"
    assert (
        classify_benchmark_error(RuntimeError("native_installed_slo_failed: concurrent capacity wave timed out"))
        == "capacity_wave_timeout"
    )
    assert classify_benchmark_error(RuntimeError("adapter response exceeded bound")) == "response_oversize"
    assert classify_benchmark_error(RuntimeError("adapter response was not JSON")) == "response_invalid"
    assert (
        classify_benchmark_error(RuntimeError("native_installed_slo_failed: fixture contract")) == "benchmark_contract"
    )
    assert classify_benchmark_error(RuntimeError("x" * 10_000)) == "benchmark_internal_failure"


def test_capacity_diagnostic_route_labels_are_bounded_without_changing_reconciliation(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    unallowlisted_label = "fixture-internal-route-identifier"

    class _FixtureMetrics:
        def __init__(self) -> None:
            self._snapshots = iter(
                (
                    {"routes": {unallowlisted_label: 2}},
                    {"routes": {unallowlisted_label: 2, "native_resident": 1}},
                )
            )

        def snapshot(self) -> dict[str, object]:
            return next(self._snapshots)

    metrics = _FixtureMetrics()
    session = _FixtureObject(daemon=_FixtureObject(_server=_FixtureObject(hook_worker=_FixtureObject(metrics=metrics))))
    session.native_overload_count = lambda: 0

    observation = Observation("codex", "PreToolUse", "1k", 1.0, "native_resident", True)
    monkeypatch.setattr(capacity, "_run_concurrent", lambda *_args, **_kwargs: ([observation], 0))
    capacity._measure_classified_wave(session, (("codex", "PreToolUse"),), 1, object())

    diagnostic = json.loads(capsys.readouterr().err)
    assert unallowlisted_label not in json.dumps(diagnostic)
    assert diagnostic["route_counters_before"] == {"unknown": 2}
    assert diagnostic["route_counters_after"] == {"native_resident": 1, "unknown": 2}
    assert diagnostic["reconciled_routes"] == {"native_resident": 1}


def test_first_cold_start_failure_is_attributed_to_cold_stage(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    class _FixtureSession:
        def __init__(self, _runtime: Path) -> None:
            self.workspace = tmp_path / "fixture-workspace"
            self.guard_home = tmp_path / "fixture-home"

        def __enter__(self) -> _FixtureSession:
            raise RuntimeError("fixture cold startup failed")

        def __exit__(self, *_args: object) -> None:
            return None

    progress = SloProgress()
    progress.configure_invocation(
        warm_iterations=1,
        cold_iterations=1,
        recovery_iterations=1,
        readiness_samples=1,
        include_capacity=False,
    )
    monkeypatch.setattr(benchmark, "AdapterSession", _FixtureSession)
    with pytest.raises(RuntimeError, match="fixture cold startup"):
        benchmark._measure_slo(
            tmp_path / "fixture-runtime",
            (("codex", "PreToolUse"),),
            warm_iterations=1,
            cold_iterations=1,
            recovery_iterations=1,
            readiness_samples=1,
            include_capacity=False,
            progress=progress,
        )

    assert progress.stage_snapshot()["cold"]["failed"] == 1
    assert progress.snapshot_failure()["stage"] == "cold"


def test_main_session_start_failure_marks_readiness_before_warm(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    sessions = [0]

    class _FixtureSession:
        def __init__(self, _runtime: Path) -> None:
            self.readiness_ms = 1.0
            sessions[0] += 1

        def __enter__(self) -> _FixtureSession:
            if sessions[0] == 2:
                raise RuntimeError("fixture readiness startup failed")
            return self

        def __exit__(self, *_args: object) -> None:
            return None

    progress = SloProgress()
    progress.configure_invocation(
        warm_iterations=1,
        cold_iterations=1,
        recovery_iterations=1,
        readiness_samples=1,
        include_capacity=False,
    )
    monkeypatch.setattr(benchmark, "AdapterSession", _FixtureSession)
    monkeypatch.setattr(benchmark, "_run_cold", lambda *_args, **_kwargs: [1.0])

    with pytest.raises(RuntimeError, match="fixture readiness startup"):
        benchmark._measure_slo(
            tmp_path / "fixture-runtime",
            (("codex", "PreToolUse"),),
            warm_iterations=1,
            cold_iterations=1,
            recovery_iterations=1,
            readiness_samples=1,
            include_capacity=False,
            progress=progress,
        )

    readiness = progress.stage_snapshot()["readiness"]
    assert readiness["attempted"] == 1
    assert readiness["failed"] == 1
    assert progress.snapshot_failure()["stage"] == "readiness"


def test_capacity_timeout_preserves_finished_observation() -> None:
    release = threading.Event()
    pre_done = threading.Event()
    post_entered = threading.Event()
    observed: list[Observation] = []
    cancelled: list[int] = []

    class _FixtureSession:
        def observe(self, _harness: str, event: str, _size: str) -> Observation:
            if event == "PostToolUse":
                post_entered.set()
                release.wait()
            observation = Observation("codex", event, "1k", 1.0, "native_resident", True)
            if event == "PreToolUse":
                pre_done.set()
            return observation

    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr(capacity, "_CONCURRENT_WAVE_TIMEOUT_SECONDS", 0.01)
    original_wait = capacity.wait

    def wait_after_pre(futures, *, timeout):
        assert pre_done.wait(timeout=2)
        assert post_entered.wait(timeout=2)
        return original_wait(futures, timeout=timeout)

    monkeypatch.setattr(capacity, "wait", wait_after_pre)
    executor = ThreadPoolExecutor(max_workers=2)
    try:
        with pytest.raises(RuntimeError, match="concurrent capacity wave timed out") as failure:
            capacity._run_concurrent(
                _FixtureSession(),
                (("codex", "PreToolUse"), ("codex", "PostToolUse")),
                2,
                executor,
                on_transport_observations=observed.extend,
                on_cancelled=lambda _stage, count: cancelled.append(count),
            )
        assert len(observed) == 1
        assert observed[0].event == "PreToolUse"
    finally:
        release.set()
        executor.shutdown(wait=True, cancel_futures=True)
        monkeypatch.undo()

    assert len(observed) == 2
    assert {item.event for item in observed} == {"PreToolUse", "PostToolUse"}
    assert cancelled == []
    assert classify_benchmark_error(failure.value) == "capacity_wave_timeout"


def test_cli_failure_writes_bounded_json(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    runtime = tmp_path / "fixture-runtime"
    runtime.write_bytes(b"fixture")
    output = tmp_path / "failed.json"

    def fail_run(*_args: object, **_kwargs: object) -> dict[str, object]:
        raise RuntimeError("fixture exception with /fixture/request")

    monkeypatch.setattr(benchmark, "run_slo", fail_run)
    monkeypatch.setattr(sys, "argv", ["bench", "--runtime", str(runtime), "--json", str(output)])

    assert benchmark.main() == 1
    parsed = json.loads(output.read_text(encoding="utf-8"))
    assert parsed["status"] == "failed"
    assert parsed["passed"] is False
    assert parsed["runtime"] is None
    assert all(value is False for value in parsed["gates"].values())
    assert "/fixture/request" not in output.read_text(encoding="utf-8")
    captured = capsys.readouterr()
    assert captured.out.startswith("{")
    assert "/fixture/request" not in captured.err
    assert "fixture exception" not in captured.err


def test_cli_unprintable_exception_writes_bounded_json(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    class _UnprintableError(RuntimeError):
        def __str__(self) -> str:
            raise AssertionError("formatter invoked")

    runtime = tmp_path / "fixture-runtime"
    runtime.write_bytes(b"fixture")
    output = tmp_path / "failed.json"

    def fail_run(*_args: object, **_kwargs: object) -> dict[str, object]:
        raise _UnprintableError()

    monkeypatch.setattr(benchmark, "run_slo", fail_run)
    monkeypatch.setattr(sys, "argv", ["bench", "--runtime", str(runtime), "--json", str(output)])

    assert benchmark.main() == 1
    rendered = output.read_text(encoding="utf-8")
    parsed = json.loads(rendered)
    assert parsed["status"] == "failed"
    assert parsed["passed"] is False
    assert all(value is False for value in parsed["gates"].values())
    captured = capsys.readouterr()
    assert "formatter invoked" not in rendered
    assert "formatter invoked" not in captured.out
    assert "formatter invoked" not in captured.err


def test_cli_export_failure_keeps_stdout_failed(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    runtime = tmp_path / "fixture-runtime"
    runtime.write_bytes(b"fixture")
    output = tmp_path / "failed.json"

    def fail_run(*_args: object, **_kwargs: object) -> dict[str, object]:
        raise RuntimeError("fixture run failed")

    original_write_text = Path.write_text

    def fail_export(path: Path, data: str, **kwargs: object) -> int:
        if path == output:
            raise OSError("fixture secret /fixture/report")
        return original_write_text(path, data, **kwargs)

    monkeypatch.setattr(benchmark, "run_slo", fail_run)
    monkeypatch.setattr(Path, "write_text", fail_export)
    monkeypatch.setattr(sys, "argv", ["bench", "--runtime", str(runtime), "--json", str(output)])

    assert benchmark.main() == 1
    captured = capsys.readouterr()
    parsed = json.loads(captured.out)
    assert parsed["status"] == "failed"
    assert parsed["passed"] is False
    assert all(value is False for value in parsed["gates"].values())
    assert "/fixture/report" not in captured.out
    assert "/fixture/report" not in captured.err
    assert "fixture secret" not in captured.err


@pytest.mark.parametrize(
    ("runtime_target", "manifest_target", "platform_tag", "valid"),
    [
        ("x86_64-linux", "x86_64-unknown-linux-musl", "manylinux_2_17_x86_64", True),
        ("x86_64-linux", "x86_64-unknown-linux-gnu", "manylinux2014_x86_64", True),
        ("x86_64-linux", "x86_64-unknown-linux-musl", "musllinux_1_2_x86_64", True),
        ("aarch64-macos", "aarch64-apple-darwin", "macosx_11_0_arm64", True),
        ("x86_64-macos", "x86_64-apple-darwin", "macosx_13_0_x86_64", True),
        ("x86_64-windows", "x86_64-pc-windows-msvc", "win_amd64", True),
        ("x86_64-linux", "x86_64-unknown-linux-musl", "win_amd64", False),
        ("x86_64-macos", "x86_64-apple-darwin", "macosx_11_0_arm64", False),
        ("x86_64-linux", "x86_64-unknown-linux-musl", "manylinux_2_17_aarch64", False),
        ("x86_64-linux", "aarch64-apple-darwin", "manylinux_2_17_x86_64", False),
        ("x86_64", "x86_64", "manylinux_2_17_x86_64", False),
    ],
)
def test_runtime_summary_carries_validated_manifest_provenance(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    runtime_target: str,
    manifest_target: str,
    platform_tag: str,
    valid: bool,
) -> None:
    artifact = tmp_path / "fixture-runtime"
    artifact.write_bytes(b"runtime")
    identity = NativeRuntimeIdentity(artifact, artifact.stat().st_size, artifact.stat().st_mtime_ns, "a" * 64)
    capabilities = NativeRuntimeCapabilities(1, "3.14.1", "b" * 64, "c" * 40, runtime_target, ("native",))
    manifest = NativeRuntimeManifest(
        "hol-guard.native-runtime.v1",
        1,
        "3.14.1",
        manifest_target,
        platform_tag,
        "c" * 40,
        "b" * 64,
        "a" * 64,
        artifact.stat().st_size,
    )
    status = NativeRuntimeStatus("auto", True, True, "native_ready", identity, capabilities, manifest)
    monkeypatch.setattr(runtime_checks, "native_runtime_status", lambda: status)
    monkeypatch.setattr(runtime_checks, "native_mode", lambda: "auto")
    monkeypatch.setattr(runtime_checks, "hook_fast_path_enabled", lambda: True)
    monkeypatch.setattr(
        runtime_checks.codex_plugin_scanner,
        "__file__",
        str(tmp_path / "fixture/site-packages/core.py"),
    )

    if not valid:
        with pytest.raises(RuntimeError, match="runtime target"):
            runtime_checks._runtime_summary(artifact)
        return

    summary = runtime_checks._runtime_summary(artifact)

    assert summary["platform_tag"] == platform_tag
    assert summary["platform_tag_target_verified"] is True
    assert summary["artifact_sha256"] == "a" * 64
    assert summary["artifact_size"] == artifact.stat().st_size
    assert summary["build_sha"] == "c" * 40
    assert "fixture-runtime" not in json.dumps(summary)
