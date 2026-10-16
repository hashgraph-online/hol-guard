from __future__ import annotations

import os
from collections import Counter
from itertools import pairwise
from pathlib import Path
from types import SimpleNamespace

import pytest

from tests import guard_daemon_acceptance_fixtures as workloads
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


def _round_trip_samples(monkeypatch: pytest.MonkeyPatch, root: Path) -> list[Counter[str]]:
    log_path = root / "resident-requests.log"
    monkeypatch.setenv("HOL_GUARD_RESIDENT_REQUEST_LOG", os.fspath(log_path))
    run_clients = workloads._run_client_reviews
    samples: list[Counter[str]] = []

    def measured_batches(clients, review, *, timeout_seconds):
        (client,) = clients
        assert client["requests"] == 72
        for start in range(0, 72, 24):
            run_clients(
                [{**client, "requests": 24}],
                lambda harness, session, index, offset=start: review(harness, session, offset + index),
                timeout_seconds=timeout_seconds,
            )
            # Every client response is complete, but this daemon has not stopped.
            # One lifecycle makes startup traffic common to all sample prefixes.
            samples.append(
                Counter(
                    operation for operation in _measured_operations(log_path) if operation not in _BACKGROUND_OPERATIONS
                )
            )

    with monkeypatch.context() as scope:
        scope.setattr(workloads, "_run_client_reviews", measured_batches)
        result = run_workload(_pi_workload(72), root=root)
    assert result.requests == result.routine_allowed + result.secrets_denied == 72
    assert result.generic_failures == 0
    assert len(samples) == 3 and sum(samples[0].values()) > 0
    return samples


def _assert_round_trip_growth(samples: list[Counter[str]]) -> None:
    for before, after in pairwise(samples):
        growth = after - before
        assert sum(growth.values()) <= 24 * _RESIDENT_ROUND_TRIPS_PER_PI_HOOK, growth


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
    _assert_round_trip_growth(_round_trip_samples(monkeypatch, tmp_path))


@pytest.mark.parametrize("extra", ["none", "one", "per-request"])
def test_rpc_growth_excludes_lifecycle_traffic_but_detects_extra_measured_calls(tmp_path, monkeypatch, extra):
    log_path = tmp_path / "resident-requests.log"
    observed = []

    def clients(clients, review, *, timeout_seconds):
        for client in clients:
            for index in range(client["requests"]):
                review(client["harness"], client["client"], index)

    def workload(spec, *, root):
        log_path.write_bytes(b"W\nhook_direct\n")

        def review(harness, session, index):
            observed.append(index)
            with log_path.open("ab") as output:
                output.write(b"hook_direct\ndaemon_route\n1\n")
                if extra == "per-request" or (extra == "one" and index == 35):
                    output.write(b"hook_direct\n")

        workloads._run_client_reviews(spec["clients"], review, timeout_seconds=1)
        # Teardown work must not change a measurement of completed hook calls.
        with log_path.open("ab") as output:
            output.write(b"hook_direct\n" * 17)
        return SimpleNamespace(requests=72, routine_allowed=64, secrets_denied=8, generic_failures=0)

    monkeypatch.setattr(workloads, "_run_client_reviews", clients)
    monkeypatch.setattr(__name__ + ".run_workload", workload)
    samples = _round_trip_samples(monkeypatch, tmp_path)
    assert observed == list(range(72))
    assert [sum(sample.values()) for sample in samples] == (
        [73, 145, 217] if extra == "none" else [97, 193, 289] if extra == "per-request" else [73, 146, 218]
    )
    if extra == "none":
        _assert_round_trip_growth(samples)
    else:
        with pytest.raises(AssertionError):
            _assert_round_trip_growth(samples)


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
