"""Regression tests for shared HTTP test helpers."""

from __future__ import annotations

import urllib.error
import urllib.request

import pytest

from tests.support.network import urlopen_json


class _JsonResponse:
    def __init__(self, payload: bytes) -> None:
        self._payload = payload

    def __enter__(self) -> _JsonResponse:
        return self

    def __exit__(self, *_args: object) -> bool:
        return False

    def read(self) -> bytes:
        return self._payload


def test_urlopen_json_retries_connection_reset(monkeypatch: pytest.MonkeyPatch) -> None:
    attempts = {"count": 0}

    def fake_urlopen(_request: object, timeout: float | None = None) -> _JsonResponse:
        del timeout
        attempts["count"] += 1
        if attempts["count"] == 1:
            raise ConnectionResetError(104, "Connection reset by peer")
        return _JsonResponse(b'{"decision":"deny"}')

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    monkeypatch.setattr("tests.support.network.time.sleep", lambda _seconds: None)

    payload = urlopen_json(urllib.request.Request("http://127.0.0.1/v1/hooks/pi"))

    assert payload == {"decision": "deny"}
    assert attempts["count"] == 2


def test_urlopen_json_does_not_retry_http_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    attempts = {"count": 0}

    def fake_urlopen(_request: object, timeout: float | None = None) -> _JsonResponse:
        del timeout
        attempts["count"] += 1
        raise urllib.error.HTTPError(
            "http://127.0.0.1/v1/hooks/pi",
            503,
            "Service Unavailable",
            {},
            None,
        )

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    monkeypatch.setattr("tests.support.network.time.sleep", lambda _seconds: None)

    with pytest.raises(urllib.error.HTTPError):
        urlopen_json(urllib.request.Request("http://127.0.0.1/v1/hooks/pi"))

    assert attempts["count"] == 1


def test_urlopen_json_retries_connection_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    attempts = {"count": 0}

    def fake_urlopen(_request: object, timeout: float | None = None) -> _JsonResponse:
        del timeout
        attempts["count"] += 1
        if attempts["count"] == 1:
            raise urllib.error.URLError(ConnectionRefusedError(111, "Connection refused"))
        return _JsonResponse(b'{"decision":"deny"}')

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    monkeypatch.setattr("tests.support.network.time.sleep", lambda _seconds: None)

    payload = urlopen_json(urllib.request.Request("http://127.0.0.1/v1/hooks/pi"))

    assert payload == {"decision": "deny"}
    assert attempts["count"] == 2
