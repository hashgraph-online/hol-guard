from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from scripts.bench_guard_native_installed_slo import _prime_load_executor


def test_load_executor_is_fully_started_before_rss_baseline() -> None:
    with ThreadPoolExecutor(max_workers=4) as executor:
        assert _prime_load_executor(executor, 4) == 4
