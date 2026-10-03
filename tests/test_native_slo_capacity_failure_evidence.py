"""Capacity failures stay failures, with bounded request-level evidence."""

from __future__ import annotations

import http.client
import json
from concurrent.futures import Future, ThreadPoolExecutor
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.adapters.codex_daemon_hook_auth import _DaemonResponseError
from scripts import native_slo_capacity as capacity
from scripts.native_slo_adapter import Observation
from scripts.native_slo_failure_details import failure_details


@pytest.mark.parametrize(
    "error,expected",
    [
        (http.client.IncompleteRead(b"private-response", 200), "http_incomplete_body"),
        (http.client.RemoteDisconnected("private-server"), "http_disconnected_before_response"),
        (http.client.BadStatusLine("private-response"), "http_invalid_status"),
        (http.client.HTTPException("private-response"), "http_protocol_error"),
        (http.client.NotConnected("private-response"), "http_protocol_error"),
        (_DaemonResponseError(401, "private-token", authenticated=False), "daemon_http_status"),
        (_DaemonResponseError(500, "private-path", authenticated=True), "daemon_http_status"),
        (TimeoutError("private-path"), "transport_timeout"),
        (ConnectionResetError("private-address"), "connection_reset"),
    ],
)
def test_wrapped_transport_cause_is_reported_without_private_messages(error, expected: str) -> None:
    wrapper = RuntimeError("adapter request failed")
    wrapper.__cause__ = error
    details = failure_details(wrapper)
    assert details["cause"] == expected
    assert "private" not in json.dumps(details)


def test_untrusted_exception_formatter_is_never_called() -> None:
    class UntrustedError(Exception):
        def __str__(self) -> str:
            pytest.fail("exception formatting must not run in diagnostic generation")

    error = UntrustedError("private-response")
    error.__cause__ = error
    assert failure_details(error) == {"category": "benchmark_internal_failure", "cause": "unclassified"}


def test_concurrent_errors_retain_counts_and_fail_closed_with_safe_diagnostics(capsys) -> None:
    def observe(harness, event, size):
        if harness == "codex":
            return Observation(harness, event, size, 1.0, "native_resident", True)
        raise http.client.IncompleteRead(b"private-response-content", 13)

    with ThreadPoolExecutor(max_workers=4) as executor:
        observations, errors = capacity._run_concurrent(
            SimpleNamespace(observe=observe),
            (("codex", "PreToolUse"), ("pi", "PreToolUse")),
            4,
            executor,
            stage="capacity_prewarm",
        )
    assert len(observations) == 2 and errors == 2
    text = capsys.readouterr().err
    assert "private" not in text
    assert json.loads(text) == {
        "schema": "hol-guard.native-capacity-request-failures.v1",
        "stage": "capacity_prewarm",
        "submitted": 4,
        "responses": 2,
        "errors": 2,
        "categories": {"transport_error": 2},
        "causes": {"http_incomplete_body": 2},
    }


def test_prewarm_still_rejects_a_diagnosed_transport_failure(monkeypatch, capsys) -> None:
    def observe(*_args):
        raise http.client.RemoteDisconnected("private-address")

    monkeypatch.setattr(capacity, "_prime_load_executor", lambda *_: None)
    with pytest.raises(RuntimeError, match="capacity prewarm did not complete every request"):
        capacity._prewarm_capacity_workers(SimpleNamespace(observe=observe), (("pi", "PreToolUse"),), 2)
    diagnostic = json.loads(capsys.readouterr().err)
    assert diagnostic["errors"] == diagnostic["submitted"] == 16
    assert diagnostic["responses"] == 0
    assert diagnostic["stage"] == "capacity_prewarm"


def test_daemon_error_details_and_formatter_are_not_inspected() -> None:
    class PrivateDaemonError(_DaemonResponseError):
        def __str__(self) -> str:
            pytest.fail("daemon error formatting must not run")

    error = PrivateDaemonError(403, "private-response-body", authenticated=True)
    wrapper = RuntimeError("adapter request failed")
    wrapper.__cause__ = error
    assert failure_details(wrapper) == {"category": "response_status", "cause": "daemon_http_status"}


def test_unrecognized_stage_is_not_copied_into_diagnostic(capsys) -> None:
    from scripts.native_slo_failure_details import report_request_failures

    report_request_failures(
        [failure_details(TimeoutError())],
        stage="private-host/token",
        submitted=1,
        responses=0,
        errors=1,
    )
    diagnostic = capsys.readouterr().err
    assert "private" not in diagnostic
    assert json.loads(diagnostic)["stage"] == "unknown"


@pytest.mark.parametrize("with_observer", [False, True])
def test_timeout_keeps_completed_failure_evidence_without_waiting(monkeypatch, capsys, with_observer) -> None:
    completed = Future()
    completed.set_result(Observation("codex", "PreToolUse", "1k", 1.0, "native_resident", True))
    failed = Future()
    failed.set_exception(http.client.IncompleteRead(b"private-content", 12))
    unfinished = Future()
    queued = iter([completed, failed, unfinished])
    shutdowns = []
    received = []
    executor = SimpleNamespace(
        submit=lambda *_: next(queued),
        shutdown=lambda **kwargs: shutdowns.append(kwargs),
    )
    monkeypatch.setattr(capacity, "wait", lambda *_args, **_kwargs: ({completed, failed}, {unfinished}))
    kwargs = {"on_transport_observations": received.extend} if with_observer else {}
    with pytest.raises(RuntimeError, match="concurrent capacity wave timed out"):
        capacity._run_concurrent(
            SimpleNamespace(),
            (("codex", "PreToolUse"),),
            3,
            executor,
            stage="capacity_prewarm",
            **kwargs,
        )
    assert unfinished.cancelled()
    assert shutdowns == [{"wait": False, "cancel_futures": True}]
    assert received == ([completed.result()] if with_observer else [])
    diagnostic = json.loads(capsys.readouterr().err)
    assert diagnostic["submitted"] == 3
    assert diagnostic["responses"] == diagnostic["errors"] == 1
    assert diagnostic["stage"] == "capacity_prewarm"
    assert diagnostic["causes"] == {"http_incomplete_body": 1}
    assert "private" not in json.dumps(diagnostic)
