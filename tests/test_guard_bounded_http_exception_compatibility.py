"""Keep request error accounting compatible with the supported Python 3.10 API."""

from __future__ import annotations

import builtins
import errno
import sys
from types import ModuleType

import pytest
from codex_plugin_scanner.guard.daemon import bounded_http


class _PlainOSError(OSError):
    """Retain the errno branch instead of OSError's automatic subclass selection."""


@pytest.fixture(params=("native", "python310"))
def handler_context(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch):
    if request.param == "python310":
        # Only this module's import lookup sees the older API. The real process
        # sys module and its active exception context remain intact.
        legacy_sys = ModuleType("sys")
        legacy_sys.exc_info = sys.exc_info

        def import_for_handler(name, *args, **kwargs):
            if name == "sys":
                return legacy_sys
            return builtins.__import__(name, *args, **kwargs)

        monkeypatch.setattr(bounded_http, "__import__", import_for_handler, raising=False)

    metrics = bounded_http._Metrics()
    monkeypatch.setattr(bounded_http, "_METRICS", metrics)
    server = object.__new__(bounded_http.BoundedThreadingHTTPServer)
    fallback = []

    def parent_error_handler(instance, connection, address):
        fallback.append((instance, connection, address, sys.exc_info()[1]))

    monkeypatch.setattr(bounded_http.ThreadingHTTPServer, "handle_error", parent_error_handler)
    return server, metrics, fallback


@pytest.mark.parametrize(
    ("error", "timeouts", "aborts", "uses_parent"),
    (
        (TimeoutError("fixture timeout"), 1, 0, False),
        (BrokenPipeError("fixture disconnect"), 0, 1, False),
        (ConnectionAbortedError("fixture disconnect"), 0, 1, False),
        (ConnectionResetError("fixture disconnect"), 0, 1, False),
        (_PlainOSError(errno.EPIPE, "fixture errno"), 0, 1, False),
        (_PlainOSError(errno.ECONNABORTED, "fixture errno"), 0, 1, False),
        (_PlainOSError(errno.ECONNRESET, "fixture errno"), 0, 1, False),
        (_PlainOSError(errno.ETIMEDOUT, "fixture errno"), 0, 1, False),
        (ValueError("fixture unexpected failure"), 0, 0, True),
    ),
)
def test_active_request_error_keeps_metrics_and_parent_fallback(
    handler_context, error: Exception, timeouts: int, aborts: int, uses_parent: bool
) -> None:
    server, metrics, fallback = handler_context
    connection = object()
    address = ("127.0.0.1", 1)
    try:
        raise error
    except Exception:
        server.handle_error(connection, address)
        assert sys.exc_info()[1] is error

    snapshot = metrics.snapshot()
    assert snapshot.timeouts == timeouts
    assert snapshot.client_aborts == aborts
    assert (snapshot.active, snapshot.accepted, snapshot.rejected) == (0, 0, 0)
    assert fallback == ([(server, connection, address, error)] if uses_parent else [])


def test_missing_active_error_still_reaches_parent(handler_context) -> None:
    server, metrics, fallback = handler_context
    connection = object()
    address = ("127.0.0.1", 1)
    assert sys.exc_info()[1] is None
    server.handle_error(connection, address)
    assert fallback == [(server, connection, address, None)]
    assert metrics.snapshot().timeouts == metrics.snapshot().client_aborts == 0


def test_parent_handler_failure_is_not_suppressed(handler_context, monkeypatch: pytest.MonkeyPatch) -> None:
    server, metrics, _fallback = handler_context
    failure = RuntimeError("fixture parent failure")

    def failing_parent(*args):
        raise failure

    monkeypatch.setattr(bounded_http.ThreadingHTTPServer, "handle_error", failing_parent)
    try:
        raise ValueError("fixture unexpected failure")
    except ValueError:
        with pytest.raises(RuntimeError) as captured:
            server.handle_error(object(), ("127.0.0.1", 1))

    assert captured.value is failure
    assert metrics.snapshot().timeouts == metrics.snapshot().client_aborts == 0
