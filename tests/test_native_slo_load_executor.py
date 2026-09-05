from __future__ import annotations

import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

from scripts import bench_guard_native_installed_slo as benchmark
from scripts.native_slo_session import AdapterSession


def test_load_executor_is_fully_started_before_rss_baseline() -> None:
    with ThreadPoolExecutor(max_workers=4) as executor:
        assert benchmark._prime_load_executor(executor, 4) == 4


def test_timed_out_capacity_wave_aborts_before_next_wave(monkeypatch: pytest.MonkeyPatch) -> None:
    def slow_observe(*_args: object) -> object:
        time.sleep(0.02)
        return object()

    session = cast(AdapterSession, SimpleNamespace(observe=slow_observe))
    monkeypatch.setattr(benchmark, "_CONCURRENT_WAVE_TIMEOUT_SECONDS", 0.001)

    with ThreadPoolExecutor(max_workers=1) as executor:
        with pytest.raises(RuntimeError, match="concurrent capacity wave timed out"):
            benchmark._run_concurrent(session, (("codex", "PreToolUse"),), 1, executor)


def test_measure_slo_isolates_c16_then_primes_c64_before_rss_baseline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, int | None]] = []

    class FakeSession:
        def __init__(self, _runtime: Path) -> None:
            runner = SimpleNamespace(stats=lambda: {})
            self.daemon = SimpleNamespace(_server=SimpleNamespace(hook_process_runner=runner))
            self.readiness_ms = 1.0

        def __enter__(self) -> FakeSession:
            return self

        def __exit__(self, _exc_type: object, _exc: object, _tb: object) -> None:
            return None

        def observe(self, *_args: object) -> SimpleNamespace:
            return SimpleNamespace(allowed=True, route="native_resident")

        def native_overload_count(self) -> int:
            return 0

    def fake_prime(executor: ThreadPoolExecutor, concurrency: int) -> int:
        calls.append(("prime", id(executor)))
        return concurrency

    def fake_prewarm(
        _session: object,
        _routes: object,
        _concurrency: int,
        executor: ThreadPoolExecutor,
    ) -> tuple[list[object], int]:
        calls.append(("baseline-warmup", id(executor)))
        return [], 0

    def fake_baseline(warmup: Callable[[], object], **_kwargs: object) -> int:
        calls.append(("baseline-start", None))
        warmup()
        calls.append(("baseline-end", None))
        return 100

    def fake_concurrent(
        _session: object,
        _routes: object,
        concurrency: int,
        executor: ThreadPoolExecutor,
    ) -> tuple[list[object], int]:
        calls.append((f"c{concurrency}", id(executor)))
        return [], 0

    monkeypatch.setattr(benchmark, "AdapterSession", FakeSession)
    monkeypatch.setattr(benchmark, "_run_cold", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(benchmark, "_run_warm", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(benchmark, "_run_sizes", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(benchmark, "_run_recovery", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(benchmark, "_stabilize_ready_hook_workers", lambda *_args, **_kwargs: 2)
    monkeypatch.setattr(benchmark, "_prime_load_executor", fake_prime)
    monkeypatch.setattr(benchmark, "_prewarm_ready_hook_workers", fake_prewarm)
    monkeypatch.setattr(benchmark, "_steady_state_rss_baseline", fake_baseline)
    monkeypatch.setattr(benchmark, "_run_concurrent", fake_concurrent)
    monkeypatch.setattr(benchmark, "process_rss_bytes", lambda: 100)

    benchmark._measure_slo(
        Path("/tmp/unused-runtime"),
        (("codex", "PreToolUse"),),
        warm_iterations=1,
        cold_iterations=1,
        recovery_iterations=1,
        readiness_samples=1,
        include_capacity=True,
    )

    assert [name for name, _ in calls] == [
        "c16",
        "prime",
        "baseline-start",
        "baseline-warmup",
        "baseline-end",
        "c64",
    ]
    executor_by_call = {name: executor_id for name, executor_id in calls if executor_id is not None}
    assert executor_by_call["c16"] != executor_by_call["c64"]
    assert executor_by_call["prime"] == executor_by_call["baseline-warmup"] == executor_by_call["c64"]
