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

from codex_plugin_scanner.guard import native_supply_chain_egress as egress


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

    monkeypatch.setattr(
        urllib.request, "urlopen", lambda request, timeout=None, context=None: callback(request, timeout)
    )
    monkeypatch.setattr(
        urllib.request,
        "build_opener",
        lambda *_handlers: _StubOpener(callback),
    )
    # The double stands in for urllib, so the suite's loopback-only rule is lifted
    # for HTTP in this process. Archive fetches and spawned helpers stay refused.
    lift_test_loopback_rule(monkeypatch, egress.TEST_RULE_HTTP)


def lift_test_loopback_rule(monkeypatch: pytest.MonkeyPatch, kind: str) -> None:
    """Lift the suite's loopback-only egress rule for one class a test fakes.

    Only this process is affected: helpers a test spawns inherit the flag and
    keep refusing every class, and the other class here stays refused.
    """

    rule = egress.refused_by_test_loopback_rule

    def lifted(url: str, *, kind: str) -> bool:
        return kind != lifted_kind and rule(url, kind=kind)

    lifted_kind = kind
    monkeypatch.setattr(egress, "refused_by_test_loopback_rule", lifted)


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
        except urllib.error.URLError as exc:
            last_error = exc
            time.sleep(0.05)
        except (
            BrokenPipeError,
            ConnectionAbortedError,
            ConnectionResetError,
            TimeoutError,
            http.client.IncompleteRead,
            http.client.RemoteDisconnected,
        ) as exc:
            last_error = exc
            time.sleep(0.05)
    assert last_error is not None
    raise last_error
