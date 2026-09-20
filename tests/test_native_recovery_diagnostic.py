from __future__ import annotations

import json
import threading
from types import SimpleNamespace
from typing import Any, cast

import pytest

import scripts.bench_guard_native_installed_slo as benchmark
import scripts.native_recovery_diagnostic as diagnostic
from codex_plugin_scanner.guard.adapters import claude_daemon_hook_transport as transport
from codex_plugin_scanner.guard.daemon import hook_process_slot_review as slots
from codex_plugin_scanner.guard.daemon.hook_process_worker import HookWorkerSlot
from scripts import native_slo_session
from scripts.native_slo_adapter import Observation


def _response(*, allowed: bool = True) -> Observation:
    return Observation("claude-code", "PostToolUse", "1k", 1.0, "native_resident", allowed)


def test_actual_wrapped_calls_preserve_results_and_exclude_unrelated_threads(monkeypatch: pytest.MonkeyPatch) -> None:
    now = [1.0]
    monkeypatch.setattr(diagnostic, "_clock", lambda: now[0])
    private = {"secret": "synthetic-do-not-retain"}
    calls: list[object] = []

    def identity(value: object) -> object:
        calls.append(value)
        now[0] += 0.005
        return private

    monkeypatch.setattr(transport, "_authenticated_state", identity)
    observer = diagnostic.RecoveryObservation(object())
    with observer.attach():
        # An actual call before the timed sample must remain unobserved.
        assert transport._authenticated_state("synthetic-do-not-retain") is private
        observer.begin()
        assert transport._authenticated_state("synthetic-do-not-retain") is private
        other = threading.Thread(target=transport._authenticated_state, args=("synthetic-do-not-retain",))
        other.start()
        other.join(timeout=1)
        assert not other.is_alive()
        report = observer.finish(index=0, rearmed=False, elapsed_ms=10.0, response=_response())

    assert transport._authenticated_state is identity
    assert calls == ["synthetic-do-not-retain"] * 3
    phases: Any = report["phases"]
    assert phases["identity_read"] == {
        "started": 1,
        "completed": 1,
        "raised": 0,
        "elapsed_ms": 5.0,
        "max_ms": 5.0,
        "invalid_clock": 0,
    }
    assert "synthetic-do-not-retain" not in json.dumps(report)
    assert "secret" not in json.dumps(report)


def test_worker_round_trip_is_scoped_to_the_observed_runner(monkeypatch: pytest.MonkeyPatch) -> None:
    now = [1.0]
    monkeypatch.setattr(diagnostic, "_clock", lambda: now[0])
    reply = object()
    unused_slot = cast(HookWorkerSlot, object())

    def round_trip(*_args: object, **_kwargs: object) -> object:
        now[0] += 0.015
        return reply

    class Runner:
        def stats(self) -> dict[str, object]:
            return {"workers": 2, "ready": 2, "failures": 0, "private": "omit-me"}

        def review(self) -> object:
            return slots._send_review_to_slot(unused_slot, {}, 0)

    runner = Runner()
    session = SimpleNamespace(daemon=SimpleNamespace(_server=SimpleNamespace(hook_process_runner=runner)))
    monkeypatch.setattr(slots, "_send_review_to_slot", round_trip)
    observer = diagnostic.RecoveryObservation(session)
    with observer.attach():
        observer.begin()
        assert slots._send_review_to_slot(unused_slot, {}, 0) is reply
        assert runner.review() is reply
        report = observer.finish(index=0, rearmed=False, elapsed_ms=30.0, response=_response())

    assert "review" not in vars(runner)
    phases: Any = report["phases"]
    assert phases["worker_dispatch"]["started"] == phases["worker_round_trip"]["started"] == 1
    assert phases["worker_round_trip"]["elapsed_ms"] == 15.0
    assert "omit-me" not in json.dumps(report)


def test_original_exception_and_concurrent_replacement_survive_observation(monkeypatch: pytest.MonkeyPatch) -> None:
    failure = RuntimeError("synthetic-private-error")

    def failing(*_args: object, **_kwargs: object) -> object:
        raise failure

    def replacement(*_args: object, **_kwargs: object) -> object:
        return None

    monkeypatch.setattr(transport, "_authenticated_state", failing)
    observer = diagnostic.RecoveryObservation(object())
    with observer.attach():
        observer.begin()
        with pytest.raises(RuntimeError) as raised:
            transport._authenticated_state("private-path")
        assert raised.value is failure
        transport._authenticated_state = replacement  # type: ignore[assignment]
        report = observer.finish(index=0, rearmed=False, elapsed_ms=1.0, response=_response())

    assert transport._authenticated_state is replacement
    phases: Any = report["phases"]
    assert phases["identity_read"]["raised"] == 1
    assert "synthetic-private-error" not in json.dumps(report)
    assert "private-path" not in json.dumps(report)


@pytest.mark.parametrize("clock", [float("nan"), float("inf"), -1.0])
def test_invalid_clock_never_changes_the_original_result(clock: float, monkeypatch: pytest.MonkeyPatch) -> None:
    samples = iter((1.0, clock))
    monkeypatch.setattr(diagnostic, "_clock", lambda: next(samples))
    result = object()
    observer = diagnostic.RecoveryObservation(object())
    observer.begin()
    wrapped = observer._wrap("identity_read", lambda: result, lambda: True)
    assert wrapped() is result
    report = observer.finish(index=0, rearmed=False, elapsed_ms=1.0, response=_response())
    phases: Any = report["phases"]
    assert phases["identity_read"]["completed"] == 1
    assert phases["identity_read"]["invalid_clock"] == 1
    assert phases["identity_read"]["elapsed_ms"] == 0


def test_slow_success_keeps_its_latency_and_emits_bounded_evidence(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    now = [1.0]
    monkeypatch.setattr(benchmark.time, "perf_counter", lambda: now[0])
    monkeypatch.setattr(diagnostic, "_clock", lambda: now[0])

    def authenticated(*_args: object, **_kwargs: object) -> str:
        now[0] += 2.062357
        return "synthetic-private-response"

    class Session:
        stopped = False
        requests = 0

        def observe(self, harness: str, event: str, size_class: str) -> Observation:
            del harness, event, size_class
            self.requests += 1
            if self.stopped:
                native_slo_session.authenticated_claude_hook_response(
                    state_path="private-state", query="private-query", data="private-body", timeout_seconds=5
                )
            return _response()

        def stop_resident(self) -> bool:
            self.stopped = True
            return True

        def rearm_policy_after_resident_stop(self) -> None:
            raise AssertionError("autonomous recovery must not explicitly rearm")

    monkeypatch.setattr(native_slo_session, "authenticated_claude_hook_response", authenticated)
    session = Session()
    reports: list[dict[str, object]] = []
    values = benchmark._run_recovery(session, 1, diagnostics=reports)

    assert values == pytest.approx([2062.357])
    assert session.requests == 2
    assert len(reports) == 1
    report = reports[0]
    assert report["elapsed_ms"] == 2062.357
    assert report["allowed"] is True
    phases: Any = report["phases"]
    assert phases["authenticated_adapter"]["elapsed_ms"] == 2062.357
    assert phases["publisher_attempt"]["started"] == 0
    emitted = capsys.readouterr().err
    assert emitted.startswith("native_recovery_observation: ")
    assert "private-state" not in emitted and "private-body" not in emitted and "private-response" not in emitted


def test_diagnostic_overhead_is_inside_measurement_and_reporting_failure_cannot_hide_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from tests.test_native_slo_recovery import _RecoverySession

    now = [1.0]
    monkeypatch.setattr(benchmark.time, "perf_counter", lambda: now[0])

    def begin(_self: object) -> None:
        now[0] += 0.007

    def finish(*_args: object, **_kwargs: object) -> object:
        raise RuntimeError("diagnostic-only-error")

    monkeypatch.setattr(diagnostic.RecoveryObservation, "begin", begin)
    monkeypatch.setattr(diagnostic.RecoveryObservation, "finish", finish)
    assert benchmark._run_recovery(_RecoverySession(), 1) == pytest.approx([7.0])
    with pytest.raises(RuntimeError, match="recovery sample 0 failed"):
        benchmark._run_recovery(_RecoverySession(allowed=False), 1)


def test_publisher_facts_are_finite_and_unknown_fields_never_survive() -> None:
    publisher = SimpleNamespace(_last_error="private-detail", _acked=True, _failure_count=10**8, _epoch=True)
    result = diagnostic._publisher_state(publisher)
    assert result == {"available": True, "acked": True, "epoch": None, "failures": 999, "error": "other"}


def test_raised_first_adapter_call_has_no_invented_response_or_retry(capsys: pytest.CaptureFixture[str]) -> None:
    from tests.test_native_slo_recovery import _RecoverySession

    failure = OSError("synthetic-private-transport-error")

    class RaisingSession(_RecoverySession):
        def observe(self, harness: str, event: str, size_class: str) -> Observation:
            if self._stopped:
                self.events.append("observe")
                raise failure
            return super().observe(harness, event, size_class)

    session = RaisingSession()
    with pytest.raises(OSError) as raised:
        benchmark._run_recovery(session, 3)
    assert raised.value is failure
    assert session.events == ["observe", "stop", "observe"]
    emitted = capsys.readouterr().err
    report = json.loads(emitted.removeprefix("native_recovery_observation: "))
    assert report["outcome"] == "raised"
    assert report["allowed"] is None
    assert report["route"] == "unavailable"
    assert "synthetic-private-transport-error" not in emitted
