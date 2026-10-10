from __future__ import annotations

import os
from pathlib import Path

import pytest

from tests.guard_daemon_acceptance_fixtures import WorkloadSpec, run_workload

# Native round trips each pi PostToolUse hook may spend: route facts, hook edge
# review and hook adapter. A new port must fold its work into these or memoize
# it; an extra un-memoized round trip per request lands directly in hook p95.
_RESIDENT_ROUND_TRIPS_PER_PI_HOOK = 3


def _pi_workload(requests: int) -> WorkloadSpec:
    return {
        "id": f"rpc-budget-{requests}",
        "clients": [{"harness": "pi", "client": "pi-1", "requests": requests, "concurrency": 4}],
        "secret_stride": 10,
    }  # type: ignore[return-value]


def _round_trips(monkeypatch: pytest.MonkeyPatch, root: Path, requests: int) -> int:
    log_path = root / "resident-requests.log"
    monkeypatch.setenv("HOL_GUARD_RESIDENT_REQUEST_LOG", os.fspath(log_path))
    result = run_workload(_pi_workload(requests), root=root)
    assert result.requests == requests
    if not log_path.is_file():
        return 0
    return len(log_path.read_bytes().splitlines())


@pytest.mark.usefixtures("native_hook_force")
def test_pi_post_tool_hook_resident_round_trips_per_request_are_bounded(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    small_root = tmp_path / "small"
    large_root = tmp_path / "large"
    small_root.mkdir()
    large_root.mkdir()
    small = _round_trips(monkeypatch, small_root, 24)
    large = _round_trips(monkeypatch, large_root, 48)
    # The difference isolates per-request cost from daemon start-up traffic.
    assert (large - small) <= 24 * _RESIDENT_ROUND_TRIPS_PER_PI_HOOK, (small, large)
