from __future__ import annotations

import threading
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

from codex_plugin_scanner.guard import native_resident_client as clients
from scripts import native_slo_capacity as capacity
from scripts.native_slo_adapter import Observation
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

    session = cast(AdapterSession, cast(object, SimpleNamespace(observe=slow_observe)))
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


def test_capacity_proof_warms_resident_clients_before_isolated_c16_and_c64(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, ThreadPoolExecutor | None]] = []

    class FakeSession:
        def __init__(self) -> None:
            runner = SimpleNamespace(stats=lambda: {"target": 2, "workers": 2, "ready": 2, "busy": 0})
            worker = SimpleNamespace(metrics=SimpleNamespace(snapshot=lambda: {"routes": {}}))
            self.daemon = SimpleNamespace(_server=SimpleNamespace(hook_process_runner=runner, hook_worker=worker))

        def native_overload_count(self) -> int:
            return 0

    def fake_prime(executor: ThreadPoolExecutor, concurrency: int) -> int:
        calls.append((f"prime-{concurrency}", executor))
        return concurrency

    def fake_prewarm(
        _session: object,
        _routes: object,
        concurrency: int,
        executor: ThreadPoolExecutor,
    ) -> tuple[list[object], int]:
        calls.append(("worker-warmup", executor))
        return [object() for _ in range(concurrency)], 0

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
    ) -> tuple[list[Observation], int]:
        calls.append((f"c{concurrency}", executor))
        return [Observation("codex", "PreToolUse", "1k", 0.0, "native_resident", True)] * concurrency, 0

    monkeypatch.setattr(capacity, "_stabilize_ready_hook_workers", lambda *_args, **_kwargs: 2)
    monkeypatch.setattr(capacity, "_prime_load_executor", fake_prime)
    monkeypatch.setattr(capacity, "_prewarm_ready_hook_workers", fake_prewarm)
    monkeypatch.setattr(capacity, "_steady_state_rss_baseline", fake_baseline)
    monkeypatch.setattr(capacity, "_run_concurrent", fake_concurrent)
    monkeypatch.setattr(capacity, "process_rss_bytes", lambda: 100)

    session = cast(AdapterSession, cast(object, FakeSession()))
    capacity.measure_capacity(session, (("codex", "PreToolUse"),), include_capacity=True)

    assert [name for name, _ in calls] == [
        "prime-16",
        "c16",
        "prime-16",
        "c16",
        "prime-64",
        "baseline-start",
        "worker-warmup",
        "baseline-end",
        "c64",
    ]
    executor_by_call = {name: executor for name, executor in calls if executor is not None}
    assert executor_by_call["prime-16"] is executor_by_call["c16"]
    assert executor_by_call["c16"] is not executor_by_call["c64"]
    assert calls[0][1] is calls[1][1]
    assert calls[1][1] is not calls[3][1]
    assert executor_by_call["prime-64"] is executor_by_call["worker-warmup"] is executor_by_call["c64"]


def test_native_capacity_warmup_initializes_sixteen_streams_with_two_python_workers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    started_streams: set[object] = set()
    starts_lock = threading.Lock()
    barrier = threading.Barrier(16, timeout=2)

    def framed_request(client: object, payload: bytes, *, deadline_monotonic: float) -> bytes:
        assert deadline_monotonic > time.monotonic()
        with starts_lock:
            started_streams.add(client)
        # Hold all sixteen real pool leases together, so a fast response cannot
        # hide an undersized warmup by reusing one stream sequentially.
        barrier.wait()
        return payload

    monkeypatch.setattr(clients._PersistentNativeClient, "request", framed_request)
    pool = clients._PersistentNativeClientPool(
        executable=tmp_path / "runtime", state_dir=tmp_path / "native-runtime", environment={}
    )

    class Session:
        daemon = SimpleNamespace(
            _server=SimpleNamespace(
                hook_process_runner=SimpleNamespace(stats=lambda: {"target": 2, "workers": 2, "ready": 2, "busy": 0})
            )
        )

        def observe(self, harness: str, event: str, size: str) -> Observation:
            assert pool.request(b"{}", deadline_monotonic=time.monotonic() + 3) == b"{}"
            return Observation(harness, event, size, 0.0, "native_resident", True)

    session = cast(AdapterSession, cast(object, Session()))
    routes = (("pi", "PreToolUse"),)
    try:
        capacity._prewarm_capacity_workers(session, routes, 2)
        warmed_streams = started_streams.copy()
        assert len(warmed_streams) == 16
        with ThreadPoolExecutor(max_workers=16) as executor:
            capacity._prime_load_executor(executor, 16)
            observations, errors = capacity._run_concurrent(session, routes, 16, executor)
        assert errors == 0
        assert len(observations) == 16
        assert all(item.allowed and item.route == "native_resident" for item in observations)
        assert started_streams == warmed_streams
    finally:
        pool.close()


@pytest.mark.parametrize("completed,errors", [(15, 0), (16, 1)])
def test_capacity_prewarm_rejects_incomplete_worker_initialization(
    monkeypatch: pytest.MonkeyPatch, completed: int, errors: int
) -> None:
    monkeypatch.setattr(
        capacity,
        "_run_concurrent",
        lambda *_args: ([object() for _ in range(completed)], errors),
    )
    with pytest.raises(RuntimeError, match="capacity prewarm did not complete every request"):
        capacity._prewarm_capacity_workers(cast(AdapterSession, object()), (("codex", "PreToolUse"),), 2)


@pytest.mark.parametrize(
    "failed",
    [
        {"allowed": False},
        {"route": "native_fail_safe"},
        {"overloaded": True},
    ],
)
def test_capacity_prewarm_rejects_failed_native_review(
    monkeypatch: pytest.MonkeyPatch, failed: dict[str, object]
) -> None:
    success = Observation("pi", "PreToolUse", "1k", 0.0, "native_resident", True)
    observations = [success] * 15 + [replace(success, **failed)]
    monkeypatch.setattr(capacity, "_run_concurrent", lambda *_args: (observations, 0))
    with pytest.raises(RuntimeError, match="capacity prewarm did not complete native review"):
        capacity._prewarm_capacity_workers(cast(AdapterSession, object()), (("pi", "PreToolUse"),), 2)


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
