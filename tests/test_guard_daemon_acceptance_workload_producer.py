from __future__ import annotations

import threading
from collections import Counter
from concurrent.futures import ThreadPoolExecutor

from tests.coverage_ci import under_coverage_scale
from tests.guard_daemon_acceptance_fixtures import _run_client_reviews, load_correctness_workloads


def test_two_client_workload_overlaps_declared_concurrency_without_client_starvation() -> None:
    workload = next(spec for spec in load_correctness_workloads() if spec["id"] == "pi-480-two-client-24")
    declared_concurrency = {client["client"]: client["concurrency"] for client in workload["clients"]}
    aggregate_concurrency = sum(declared_concurrency.values())
    timeout_seconds = 5.0 * under_coverage_scale(3.0)
    first_wave_ready = threading.Event()
    release = threading.Event()
    lock = threading.Lock()
    active: Counter[str] = Counter()
    maximum_active: Counter[str] = Counter()
    completed: Counter[tuple[str, int]] = Counter()

    def review(_harness: str, client: str, index: int) -> None:
        with lock:
            active[client] += 1
            maximum_active[client] = max(maximum_active[client], active[client])
            if sum(active.values()) == aggregate_concurrency:
                first_wave_ready.set()
        try:
            assert release.wait(timeout=timeout_seconds)
            with lock:
                completed[client, index] += 1
        finally:
            with lock:
                active[client] -= 1

    with ThreadPoolExecutor(max_workers=1) as producer:
        future = producer.submit(
            _run_client_reviews,
            workload["clients"],
            review,
            timeout_seconds=timeout_seconds,
        )
        try:
            assert first_wave_ready.wait(timeout=timeout_seconds)
            with lock:
                assert dict(active) == declared_concurrency
        finally:
            release.set()
        future.result(timeout=timeout_seconds)

    assert dict(maximum_active) == declared_concurrency
    assert completed == Counter(
        (client["client"], index)
        for client in workload["clients"]
        for index in range(client["requests"])
    )
