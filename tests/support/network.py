"""Explicit network stubs for authenticated Guard request tests."""

from __future__ import annotations

import http.client
import json
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from typing import Protocol

import pytest


class _UrlopenCallback(Protocol):
    def __call__(self, request: object, timeout: float | None = None) -> object: ...


class _StubOpener:
    def __init__(self, callback: _UrlopenCallback) -> None:
        self._callback = callback

    def open(self, request: object, timeout: float | None = None) -> object:
        return self._callback(request, timeout)


def stub_authenticated_urlopen(
    monkeypatch: pytest.MonkeyPatch,
    callback: Callable[..., object],
) -> None:
    """Route both public and authenticated urllib paths through one test double."""

    monkeypatch.setattr(urllib.request, "urlopen", callback)
    monkeypatch.setattr(
        urllib.request,
        "build_opener",
        lambda *_handlers: _StubOpener(callback),
    )


def urlopen_json(request: urllib.request.Request, *, timeout: float = 15, attempts: int = 3) -> dict[str, object]:
    """Read one JSON object, retrying transient HTTP disconnects."""

    last_error: BaseException | None = None
    for _ in range(attempts):
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                payload = json.loads(response.read().decode("utf-8"))
            if isinstance(payload, dict):
                return payload
            raise ValueError("hook response must be an object")
        except urllib.error.HTTPError:
            raise
        except (http.client.IncompleteRead, http.client.RemoteDisconnected, TimeoutError, urllib.error.URLError) as exc:
            last_error = exc
            time.sleep(0.05)
    assert last_error is not None
    raise last_error
