"""Explicit network stubs for authenticated Guard request tests."""

from __future__ import annotations

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
