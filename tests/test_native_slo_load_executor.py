from __future__ import annotations

import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
from typing import cast

import pytest

from scripts import native_slo_capacity as capacity
from scripts.native_slo_session import AdapterSession


def test_load_executor_is_fully_started_before_rss_baseline() -> None:
    with ThreadPoolExecutor(max_workers=4) as executor:
        assert capacity._prime_load_executor(executor, 4) == 4


def test_timed_out_capacity_wave_returns_without_waiting_for_running_worker(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def slow_observe(*_args: object) -> object:
        time.sleep(0.2)
        return object()

    session = cast(AdapterSession, SimpleNamespace(observe=slow_observe))
    monkeypatch.setattr(capacity, "_CONCURRENT_WAVE_TIMEOUT_SECONDS", 0.01)
    executor = ThreadPoolExecutor(max_workers=1)
    started = time.perf_counter()
    try:
        with pytest.raises(RuntimeError, match="concurrent capacity wave timed out"):
            capacity._run_concurrent(session, (("codex", "PreToolUse"),), 1, executor)
        elapsed = time.perf_counter() - started
        assert elapsed < 0.1
    finally:
        executor.shutdown(wait=True, cancel_futures=True)


def test_capacity_proof_prestarts_isolated_c16_then_primes_c64_before_rss_baseline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, int | None]] = []

    class FakeSession:
        def __init__(self) -> None:
            runner = SimpleNamespace(stats=lambda: {})
            self.daemon = SimpleNamespace(_server=SimpleNamespace(hook_process_runner=runner))

        def native_overload_count(self) -> int:
            return 0

    def fake_prime(executor: ThreadPoolExecutor, concurrency: int) -> int:
        calls.append((f"prime-{concurrency}", id(executor)))
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

    monkeypatch.setattr(capacity, "_stabilize_ready_hook_workers", lambda *_args, **_kwargs: 2)
    monkeypatch.setattr(capacity, "_prime_load_executor", fake_prime)
    monkeypatch.setattr(capacity, "_prewarm_ready_hook_workers", fake_prewarm)
    monkeypatch.setattr(capacity, "_steady_state_rss_baseline", fake_baseline)
    monkeypatch.setattr(capacity, "_run_concurrent", fake_concurrent)
    monkeypatch.setattr(capacity, "process_rss_bytes", lambda: 100)

    session = cast(AdapterSession, FakeSession())
    capacity.measure_capacity(session, (("codex", "PreToolUse"),), include_capacity=True)

    assert [name for name, _ in calls] == [
        "prime-16",
        "c16",
        "prime-64",
        "baseline-start",
        "baseline-warmup",
        "baseline-end",
        "c64",
    ]
    executor_by_call = {name: executor_id for name, executor_id in calls if executor_id is not None}
    assert executor_by_call["prime-16"] == executor_by_call["c16"]
    assert executor_by_call["c16"] != executor_by_call["c64"]
    assert executor_by_call["prime-64"] == executor_by_call["baseline-warmup"] == executor_by_call["c64"]


def test_capacity_proof_supports_skip_capacity(monkeypatch: pytest.MonkeyPatch) -> None:
    session = cast(AdapterSession, object())
    monkeypatch.setattr(capacity, "_stabilize_ready_hook_workers", lambda *_args, **_kwargs: 2)
    monkeypatch.setattr(capacity, "_measure_rss_and_c64", lambda *_args, **_kwargs: (100, 100, [], 0))

    measured = capacity.measure_capacity(session, (("codex", "PreToolUse"),), include_capacity=False)

    assert measured.concurrent_16 == []
    assert measured.concurrent_64 == []
    assert measured.errors_16 == 0
    assert measured.errors_64 == 0
    assert measured.rss_baseline == 100
    assert measured.rss_peak == 100
