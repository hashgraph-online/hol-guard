from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor
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
