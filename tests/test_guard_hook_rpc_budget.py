from __future__ import annotations

import os
from collections import Counter
from pathlib import Path

import pytest

from tests.guard_daemon_acceptance_fixtures import WorkloadSpec, _mark_resident_request_log, run_workload

# Native round trips each pi PostToolUse hook may spend: route facts, hook edge
# review and hook adapter. A new port must fold its work into these or memoize
# it; an extra un-memoized round trip per request lands directly in hook p95.
_RESIDENT_ROUND_TRIPS_PER_PI_HOOK = 3

# The daemon's direct-hook evidence drain pages evidence on its own wake-ups,
# off the hook path, so how often it runs depends on timing, not request count.
_BACKGROUND_OPERATIONS = frozenset({"hook_direct_evidence_drain"})


def _pi_workload(requests: int, event: str = "PostToolUse") -> WorkloadSpec:
    return {
        "id": f"rpc-budget-{requests}",
        "clients": [{"harness": "pi", "client": "pi-1", "requests": requests, "concurrency": 4}],
        "secret_stride": 10,
        "event": event,
    }


def _measured_resident_requests(log_path: Path) -> int:
    assert log_path.is_file(), "no resident request was recorded"
    lines = log_path.read_bytes().splitlines()
    assert b"W" in lines, "resident request log has no post-warmup marker"
    measured = [line for line in lines[lines.index(b"W") + 1 :] if line != b"W"]
    assert measured, "no resident request was recorded after warmup"
    return len(measured)


def _round_trips(monkeypatch: pytest.MonkeyPatch, root: Path, requests: int) -> tuple[int, Counter[str]]:
    log_path = root / "resident-requests.log"
    monkeypatch.setenv("HOL_GUARD_RESIDENT_REQUEST_LOG", os.fspath(log_path))
    result = run_workload(_pi_workload(requests), root=root)
    assert result.requests == requests
    assert _measured_resident_requests(log_path) > 0
    hook_operations = [
        operation for operation in _measured_operations(log_path) if operation not in _BACKGROUND_OPERATIONS
    ]
    return len(hook_operations), Counter(hook_operations)


def test_measured_resident_requests_ignore_warmup(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    log_path = tmp_path / "resident-requests.log"
    log_path.write_bytes(b"1\n1\n")
    monkeypatch.setenv("HOL_GUARD_RESIDENT_REQUEST_LOG", os.fspath(log_path))
    _mark_resident_request_log()
    with log_path.open("ab") as handle:
        handle.write(b"1\n")
    assert log_path.read_bytes() == b"1\n1\nW\n1\n"
    assert _measured_resident_requests(log_path) == 1


@pytest.mark.usefixtures("native_hook_force")
def test_pi_post_tool_hook_resident_round_trips_per_request_are_bounded(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    small_root = tmp_path / "small"
    large_root = tmp_path / "large"
    small_root.mkdir()
    large_root.mkdir()
    small, small_operations = _round_trips(monkeypatch, small_root, 24)
    assert small > 0
    large, large_operations = _round_trips(monkeypatch, large_root, 48)
    # The difference isolates per-request cost from daemon start-up traffic.
    per_request = large_operations - small_operations
    assert (large - small) <= 24 * _RESIDENT_ROUND_TRIPS_PER_PI_HOOK, (small, large, per_request)


def _measured_operations(log_path: Path) -> list[str]:
    lines = log_path.read_bytes().splitlines()
    return [line.decode("ascii") for line in lines[lines.index(b"W") + 1 :] if line != b"W"]


@pytest.mark.usefixtures("native_hook_force")
def test_pi_allow_and_deny_hooks_never_use_the_hook_render_op(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The edge result carries the harness response, so allow and deny skip hook_render.

    The workload mixes allows with a deny every tenth request. ``hook_render``
    only serves verdicts the daemon changes after the edge decision (saved
    approvals, queued reviews, policy repair), so it must add zero resident
    round trips to the p95 path and the per-hook budget stays unchanged.
    """

    requests = 30
    log_path = tmp_path / "resident-requests.log"
    monkeypatch.setenv("HOL_GUARD_RESIDENT_REQUEST_LOG", os.fspath(log_path))
    result = run_workload(_pi_workload(requests), root=tmp_path)
    assert result.routine_allowed > 0
    assert result.secrets_denied > 0
    operations = _measured_operations(log_path)
    assert operations
    assert "hook_render" not in operations, sorted(set(operations))
    # The evidence drain runs after the hook answers, off the p95 path, and how
    # many drains land inside the workload depends on runner timing.
    hook_operations = [operation for operation in operations if operation not in _BACKGROUND_OPERATIONS]
    assert len(hook_operations) <= requests * _RESIDENT_ROUND_TRIPS_PER_PI_HOOK + 6, Counter(operations)


def test_pi_pre_tool_allow_uses_the_edge_response_not_the_hook_render_op(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A queued review legitimately renders through the op, so this workload has no
    # secret requests: every PreToolUse is a plain allow answered by the edge result.
    requests = 20
    log_path = tmp_path / "resident-requests.log"
    monkeypatch.setenv("HOL_GUARD_RESIDENT_REQUEST_LOG", os.fspath(log_path))
    workload = _pi_workload(requests, "PreToolUse")
    workload["secret_stride"] = 0
    result = run_workload(workload, root=tmp_path)
    assert result.generic_failures == 0, result
    assert result.routine_allowed == requests, result
    operations = _measured_operations(log_path)
    assert operations
    assert "hook_render" not in operations, sorted(set(operations))
