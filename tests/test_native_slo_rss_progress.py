from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts import bench_guard_native_installed_slo as benchmark
from scripts import native_slo_capacity as capacity
from scripts.native_slo_adapter import Observation
from scripts.native_slo_benchmark_stages import _observe_with_progress
from scripts.native_slo_progress import SloProgress, incomplete_slo_result


@pytest.mark.parametrize("failure", ["initial", "request", "plateau"])
def test_rss_failure_retains_stage_and_request_accounting(failure: str) -> None:
    progress = SloProgress()
    progress.configure(
        (("codex", "PreToolUse"),),
        warm_iterations=1,
        cold_iterations=1,
        recovery_iterations=1,
        readiness_samples=1,
        include_capacity=False,
    )

    def observe(*_args: object) -> Observation:
        if failure == "request":
            raise RuntimeError("fixture request failure")
        return Observation("codex", "PreToolUse", "1k", 1.0, "native_resident", True)

    def stats() -> dict[str, int]:
        return {"target": 1, "workers": 1, "ready": 1, "busy": 0}

    session = SimpleNamespace(
        observe=observe,
        daemon=SimpleNamespace(_server=SimpleNamespace(hook_process_runner=SimpleNamespace(stats=stats))),
    )

    def baseline(run_wave: Callable[[], tuple[list[Observation], int]], **_kwargs: object) -> int:
        if failure != "initial":
            observations, errors = run_wave()
            if errors:
                raise RuntimeError("native_installed_slo_failed: resident capacity wave returned request errors")
            assert len(observations) == 1
        raise RuntimeError("native_installed_slo_failed: fixture RSS plateau unavailable")

    with pytest.MonkeyPatch.context() as monkeypatch:
        monkeypatch.setattr(capacity, "_steady_state_rss_baseline", baseline)
        with pytest.raises(RuntimeError):
            capacity._measure_rss_and_c64(
                session,
                (("codex", "PreToolUse"),),
                1,
                include_capacity=False,
                observer=lambda harness, event, size, stage: _observe_with_progress(
                    progress,
                    session,
                    harness,
                    event,
                    size,
                    stage,
                    fatal=False,
                    record_submission=False,
                ),
                progress=progress,
            )

    result = incomplete_slo_result(progress, include_capacity=False)
    stages = result["corpus"]["denominators"]
    assert result["failure"]["stage"] == "rss_baseline"
    assert stages["rss_baseline"]["planned"] == stages["rss_baseline"]["attempted"] == 1
    assert stages["rss_baseline"]["failed"] == 1
    assert stages["rss_baseline"]["completed"] == stages["rss_baseline"]["missing"] == 0
    requests = stages["rss_baseline_requests"]
    assert requests["planned"] is None
    expected_requests = int(failure != "initial")
    assert requests["submitted"] == requests["attempted"] == expected_requests
    assert requests["failed"] == int(failure == "request")
    assert requests["completed"] == int(failure == "plateau")
    assert result["passed"] is False


def test_first_readiness_sample_failure_is_not_counted_complete(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    class Session:
        def __init__(self, _runtime: Path) -> None:
            pass

        def __enter__(self) -> Session:
            return self

        def __exit__(self, *_args: object) -> None:
            pass

        @property
        def readiness_ms(self) -> float:
            raise RuntimeError("fixture readiness measurement unavailable")

    progress = SloProgress()
    progress.configure(
        (("codex", "PreToolUse"),),
        warm_iterations=1,
        cold_iterations=1,
        recovery_iterations=1,
        readiness_samples=1,
        include_capacity=False,
    )
    monkeypatch.setattr(benchmark, "AdapterSession", Session)
    monkeypatch.setattr(benchmark, "_run_cold", lambda *_args, **_kwargs: [1.0])
    with pytest.raises(RuntimeError):
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
    stages = progress.stage_snapshot()
    assert progress.snapshot_failure()["stage"] == "readiness"
    assert stages["readiness"]["failed"] == 1
    assert stages["readiness"]["completed"] == stages["warm"]["attempted"] == 0


@pytest.mark.parametrize("include_capacity", [False, True])
def test_worker_stabilization_failure_counts_operation_even_without_load_wave(
    include_capacity: bool,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    progress = SloProgress()
    progress.configure(
        (("codex", "PreToolUse"),),
        warm_iterations=1,
        cold_iterations=1,
        recovery_iterations=1,
        readiness_samples=1,
        include_capacity=include_capacity,
    )

    def fail(_session: object) -> int:
        raise RuntimeError("native_installed_slo_failed: fixture worker capacity unavailable")

    monkeypatch.setattr(capacity, "_stabilize_ready_hook_workers", fail)
    with pytest.raises(RuntimeError):
        capacity.measure_capacity(
            object(),
            (("codex", "PreToolUse"),),
            include_capacity=include_capacity,
            progress=progress,
        )
    report = incomplete_slo_result(progress, include_capacity=include_capacity)
    assert report["failure"]["stage"] == "capacity_stabilization"
    counters = report["corpus"]["denominators"]["capacity_stabilization"]
    assert counters["planned"] == counters["attempted"] == counters["failed"] == 1
    assert counters["completed"] == counters["missing"] == 0
