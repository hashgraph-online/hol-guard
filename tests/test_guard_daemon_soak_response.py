from __future__ import annotations

import json
import sys
import urllib.request
from typing import cast

import pytest

import scripts.stress_guard_daemon_runtime as runtime
from scripts import stress_guard_daemon as script
from scripts.stress_guard_daemon_proof import measured_route_counts, native_routes_passed, read_route_counts


class _Response:
    def __init__(self, payload: object) -> None:
        self.body: bytes = json.dumps(payload).encode()

    def __enter__(self) -> _Response:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def read(self, _limit: int) -> bytes:
        return self.body


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"error": "private-test-data"},
        {"decision": "deny"},
        {"decision": "review"},
        {"decision": "allow", "error": "private-test-data"},
        {"decision": "allow", "isError": True},
        {"decision": "allow", "observe_mode": True},
        {"decision": "allow", "continue": False},
        {"decision": "allow", "model_output_action": "block"},
        {"decision": "allow", "policy_action": "block"},
        {"decision": "allow", "isError": "false"},
        {"decision": "allow", "observe_mode": "false"},
        {"decision": "allow", "continue": "true"},
        {"decision": "allow", "model_output_action": []},
        {"decision": "allow", "policy_action": {}},
    ],
)
def test_stress_request_rejects_unsuccessful_json_without_retrying(
    payload: object, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = 0

    def open_response(_request: object, *, timeout: float) -> _Response:
        del timeout
        nonlocal calls
        calls += 1
        return _Response(payload)

    monkeypatch.setattr(urllib.request, "urlopen", open_response)
    with pytest.raises(RuntimeError, match="did not return an allowed decision") as error:
        _ = runtime.stress_request("http://127.0.0.1:1/v1/hooks/pi", "synthetic-token")
    assert calls == 1
    assert "private-test-data" not in str(error.value)


def test_stress_request_accepts_an_explicit_allowed_decision(monkeypatch: pytest.MonkeyPatch) -> None:
    def open_response(*_args: object, **_kwargs: object) -> _Response:
        return _Response({"decision": "allow", "reason_code": "native_exact_safe_command"})

    monkeypatch.setattr(urllib.request, "urlopen", open_response)
    assert runtime.stress_request("http://127.0.0.1:1/v1/hooks/pi", "synthetic-token") >= 0


def _details(routes: object) -> dict[str, object]:
    return {"hook_workers": {"routes": routes}, "hook_worker_routes": {}}


def test_direct_native_routes_are_counted_when_child_workers_are_idle() -> None:
    before = read_route_counts({"hook_workers": {"routes": {}}, "hook_worker_routes": {"native_resident": 64}})
    assert before is not None
    measured = measured_route_counts(
        before, {"hook_workers": {"routes": {}}, "hook_worker_routes": {"native_resident": 100_064}}
    )
    assert native_routes_passed(measured, requests=100_000)


def test_one_source_cannot_mask_the_other_sources_counter_reset() -> None:
    before = read_route_counts(
        {"hook_workers": {"routes": {"native_resident": 64}}, "hook_worker_routes": {"native_resident": 64}}
    )
    assert before is not None
    assert (
        measured_route_counts(
            before, {"hook_workers": {"routes": {"native_resident": 100_064}}, "hook_worker_routes": {}}
        )
        is None
    )


def test_native_route_proof_uses_only_the_measured_interval() -> None:
    before = read_route_counts(_details({"native_resident": 64, "native_fail_safe": 2}))
    assert before is not None
    after = _details({"native_resident": 100_067, "native_fail_safe": 2})
    measured = measured_route_counts(before, after)
    assert measured is not None
    assert measured["native_resident"] == 100_003
    assert measured["native_fail_safe"] == 0
    assert native_routes_passed(measured, requests=100_000)
    assert not native_routes_passed(measured, requests=100_004)


@pytest.mark.parametrize("route", ["native_oneshot", "native_fail_safe", "native_degraded", "python_semantic"])
def test_a_single_nonresident_decision_fails_the_native_soak(route: str) -> None:
    before = read_route_counts(_details({"native_resident": 64}))
    assert before is not None
    measured = measured_route_counts(before, _details({"native_resident": 100_064, route: 1}))
    assert measured is not None
    assert not native_routes_passed(measured, requests=100_000)


@pytest.mark.parametrize(
    "details",
    [
        None,
        {},
        {"hook_workers": {}},
        {"hook_workers": {"routes": {"native_resident": 100_000}}},
        {"hook_workers": {"routes": {}}, "hook_worker_routes": {"private-route": 0}},
        {"hook_workers": {"routes": {}}, "hook_worker_routes": {"native_resident": True}},
        _details({"native_resident": True}),
        _details({"native_resident": 100_000.0}),
        _details({"native_resident": -1}),
        _details({"native_resident": "100000"}),
        _details({"native_resident": 100_000, "untrusted-private-name": 1}),
        _details({"native_resident": 100_000, "untrusted-private-name": 0}),
    ],
)
def test_missing_or_malformed_route_evidence_cannot_pass(details: dict[str, object] | None) -> None:
    before = read_route_counts(_details({"native_resident": 64}))
    assert before is not None
    assert read_route_counts(details) is None
    measured = measured_route_counts(before, details)
    assert measured is None
    assert not native_routes_passed(measured, requests=100_000)


def test_counter_reset_and_unmeasured_results_cannot_pass() -> None:
    before = read_route_counts(_details({"native_resident": 64}))
    assert before is not None
    assert measured_route_counts(before, _details({"native_resident": 63})) is None
    assert not native_routes_passed(None, requests=100_000)
    assert not native_routes_passed({}, requests=100_000)


@pytest.mark.parametrize("enforced", [False, True])
def test_cli_requires_native_route_evidence_only_for_enforced_soak(
    enforced: bool, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    baseline = read_route_counts(_details({}))
    assert baseline is not None
    routes = measured_route_counts(baseline, _details({"native_resident": 100_000}))
    assert routes is not None
    result = script.StressResult(
        requests=100_000,
        receipts=250_000,
        responses=100_000,
        errors=0,
        p95_ms=2,
        max_ms=4,
        health_checks=1,
        health_failures=0,
        pid_stable=True,
        daemon_process_count=1,
        max_hook_latency_ms=4_500,
        database_bytes=1,
        lifecycle_events=("ready",),
        max_threads=32,
        max_file_descriptors=128,
        rss_baseline_bytes=100,
        rss_peak_bytes=109,
        rss_growth=0.09,
        transient_health_failures=0,
        native_route_delta=routes if enforced else None,
    )
    calls: list[dict[str, object]] = []

    def run_stress(**kwargs: object) -> script.StressResult:
        calls.append(kwargs)
        return result

    argv = ["stress_guard_daemon.py", "--requests=100000", "--receipts=250000"]
    if enforced:
        argv.append("--enforce-soak")
    monkeypatch.setattr(sys, "argv", argv)
    monkeypatch.setattr(script, "run_stress", run_stress)
    monkeypatch.setattr(script, "clear_proof_environment", lambda: None)
    monkeypatch.setattr(script, "proof_environment_violations", lambda: ())
    assert script.main() == 0
    assert len(calls) == 1
    assert calls[0]["require_native_routes"] is enforced
    report = cast(dict[str, object], json.loads(capsys.readouterr().out))
    assert report["soak_passed"] is enforced
    assert report["native_route_delta"] == (routes if enforced else None)
