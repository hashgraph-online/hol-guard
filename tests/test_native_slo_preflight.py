from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from scripts import bench_guard_native_installed_slo as benchmark
from scripts.native_slo_progress import SloProgress, incomplete_slo_result


@pytest.mark.parametrize("stage", ["cleanup", "runtime", "routes"])
def test_preflight_failure_keeps_own_operation_denominator(
    stage: str,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    progress = SloProgress()
    monkeypatch.setattr(benchmark, "_clear_proof_overrides", lambda: None)
    monkeypatch.setattr(benchmark, "_runtime_summary", lambda _: {})
    monkeypatch.setattr(benchmark, "route_matrix", lambda: (("codex", "PreToolUse"),))

    def fail(*_args: object) -> None:
        raise RuntimeError("fixture preflight failure")

    operation = {"cleanup": "_clear_proof_overrides", "runtime": "_runtime_summary", "routes": "route_matrix"}
    monkeypatch.setattr(benchmark, operation[stage], fail)
    with pytest.raises(RuntimeError):
        benchmark.run_slo(
            tmp_path / "fixture-runtime",
            warm_iterations=1,
            cold_iterations=1,
            recovery_iterations=1,
            readiness_samples=1,
            include_capacity=False,
            progress=progress,
        )
    report = incomplete_slo_result(progress, include_capacity=False)
    assert report["failure"]["stage"] == stage
    counters = report["corpus"]["denominators"][stage]
    assert counters["planned"] == counters["submitted"] == counters["attempted"] == counters["failed"] == 1
    assert counters["completed"] == counters["missing"] == 0
    assert report["passed"] is False


def test_missing_runtime_input_is_a_counted_failed_operation(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(sys, "argv", ["bench", "--runtime", str(tmp_path / "missing-runtime")])
    assert benchmark.main() == 1
    report = json.loads(capsys.readouterr().out)
    assert report["failure"]["stage"] == "runtime_input"
    counters = report["corpus"]["denominators"]["runtime_input"]
    assert counters["attempted"] == counters["failed"] == 1
    assert counters["completed"] == 0


def test_unowned_failure_does_not_inherit_stale_stage_or_labels(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    runtime = tmp_path / "fixture-runtime"
    runtime.write_bytes(b"fixture")

    def fail(*_args: object, progress: SloProgress, **_kwargs: object) -> dict[str, object]:
        progress.activate("warm", harness="codex")
        raise RuntimeError("fixture unowned failure")

    monkeypatch.setattr(benchmark, "run_slo", fail)
    monkeypatch.setattr(sys, "argv", ["bench", "--runtime", str(runtime)])
    assert benchmark.main() == 1
    report = json.loads(capsys.readouterr().out)
    assert report["failure"] == {"stage": "unknown", "category": "benchmark_internal_failure"}
