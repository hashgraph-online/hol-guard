from __future__ import annotations

import threading
import time
from collections import Counter

import pytest

from tests.guard_daemon_acceptance_fixtures import ClientSpec, is_pre_dispatch_refusal, run_clients


def test_mixed_client_workload_preserves_each_concurrency_and_every_request() -> None:
    clients: list[ClientSpec] = [
        {"harness": "pi", "client": "pi-1", "requests": 10, "concurrency": 2},
        {"harness": "opencode", "client": "oc-1", "requests": 9, "concurrency": 3},
    ]
    first_batch = threading.Barrier(5, timeout=3)
    lock = threading.Lock()
    active: Counter[str] = Counter()
    peak: Counter[str] = Counter()
    calls: list[tuple[str, str, int]] = []

    def review(harness: str, client: str, index: int) -> None:
        with lock:
            active[client] += 1
            peak[client] = max(peak[client], active[client])
            calls.append((harness, client, index))
        if index < {"pi-1": 2, "oc-1": 3}[client]:
            first_batch.wait()
        time.sleep(0.001)
        with lock:
            active[client] -= 1

    run_clients(clients, review, request_timeout_seconds=3)

    assert peak == {"pi-1": 2, "oc-1": 3}
    assert active == {"pi-1": 0, "oc-1": 0}
    assert sorted(calls) == sorted(
        (client["harness"], client["client"], index) for client in clients for index in range(client["requests"])
    )


@pytest.mark.parametrize(
    ("status", "reason", "refused"),
    [
        (503, "Guard daemon request capacity reached", True),
        (503, "native runtime unavailable", False),
        (503, "daemon_hook_deadline_exhausted", False),
        (408, "Guard daemon request capacity reached", False),
        (200, "Guard daemon request capacity reached", False),
    ],
)
def test_retries_require_the_exact_pre_dispatch_admission_response(status: int, reason: str, refused: bool) -> None:
    assert is_pre_dispatch_refusal(status, reason) is refused
