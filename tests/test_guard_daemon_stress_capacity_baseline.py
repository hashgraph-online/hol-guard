"""Native soak worker-capacity baseline regressions."""

from __future__ import annotations

from pathlib import Path
from typing import cast

import pytest

import scripts.stress_guard_daemon as stress_script
import scripts.stress_guard_daemon_runtime as stress_runtime


def test_soak_capacity_stabilizer_does_not_accept_initial_target(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Drive the pool to configured capacity before accepting the RSS baseline."""

    execution = stress_script._StressExecution(
        daemon_url="http://127.0.0.1:1",
        endpoint="http://127.0.0.1:1/v1/hooks/pi",
        auth_token="token",
        initial_pid=123,
        guard_home=Path("guard-home"),
    )
    reports = iter(
        (
            {"hook_workers": {"configured": 4, "target": 2, "workers": 2, "ready": 2, "busy": 0}},
            {"hook_workers": {"configured": 4, "target": 2, "workers": 2, "ready": 2, "busy": 0}},
            {"hook_workers": {"configured": 4, "target": 4, "workers": 4, "ready": 4, "busy": 0}},
        )
    )
    observed_capacity: list[tuple[int, int, int, int, int]] = []
    requests: list[str] = []

    monkeypatch.setattr(stress_script, "_WARMUP_CONCURRENCY", 4)

    def healthz_details(_execution: stress_runtime.StressExecution) -> dict[str, object]:
        """Return a stable initial target before the pool reaches its configured size."""

        report = next(reports)
        workers = cast(dict[str, object], report["hook_workers"])
        observed_capacity.append(
            tuple(cast(int, workers[name]) for name in ("configured", "target", "workers", "ready", "busy"))
        )
        return report

    def stress_request(*_args: object) -> float:
        """Record the pressure wave required to move beyond the initial target."""

        requests.append("request")
        return 1.0

    monkeypatch.setattr(stress_script, "_healthz_details", healthz_details)
    monkeypatch.setattr(stress_script, "_stress_request", stress_request)

    stress_script._stabilize_full_worker_capacity(execution)

    assert len(requests) == 3
    assert execution.latencies_ms == []
    assert observed_capacity == [
        (4, 2, 2, 2, 0),
        (4, 2, 2, 2, 0),
        (4, 4, 4, 4, 0),
    ]
