"""Actual retry attempts and completed responses retain inventory authority."""

from __future__ import annotations

import io
import socket
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from email.message import Message
from pathlib import Path
from types import SimpleNamespace, TracebackType
from typing import Any

import pytest

from codex_plugin_scanner.guard import aibom_operation_authority as authority
from codex_plugin_scanner.guard.cli.oauth_client import GuardDpopKeyMaterial
from codex_plugin_scanner.guard.runtime import runner
from tests.test_aibom_operation_authority import _context, _operation, _selected
from tests.test_oauth_connection_authority import NOW, _store


@pytest.fixture(autouse=True)
def _offline(monkeypatch: pytest.MonkeyPatch) -> None:
    def denied(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("Unexpected raw network operation")

    monkeypatch.setattr(socket, "create_connection", denied)
    monkeypatch.setattr(socket.socket, "connect", denied)


def _request(inputs: dict[str, Any]) -> urllib.request.Request:
    key = GuardDpopKeyMaterial(
        algorithm="ES256",
        private_key_pem=inputs["dpop_private_key_pem"],
        public_jwk=inputs["dpop_public_jwk"],
        public_jwk_thumbprint=inputs["dpop_public_jwk_thumbprint"],
    )
    return runner._guard_sync_request(
        {"sync_url": "https://hol.test/sync", "access_token": "synthetic", "dpop_key_material": key},
        request_url="https://hol.test/events",
        method="POST",
        data=b'{"events":[]}',
    )


class _Response(io.BytesIO):
    def __init__(self, *, read_action: Callable[[], None] | None = None, exit_action: Callable[[], None] | None = None):
        super().__init__(b'{"accepted":1}')
        self.read_action = read_action
        self.exit_action = exit_action

    def read(self, size: int | None = -1) -> bytes:
        body = super().read(size)
        if self.read_action is not None:
            self.read_action()
        return body

    def __exit__(
        self, exc_type: type[BaseException] | None, exc_value: BaseException | None, traceback: TracebackType | None
    ) -> None:
        super().__exit__(exc_type, exc_value, traceback)
        if self.exit_action is not None:
            self.exit_action()


def _error(
    mode: str, request: urllib.request.Request, body: io.BytesIO | None = None, *, nonce: str = "controlled-nonce"
) -> OSError:
    if mode == "timeout":
        return TimeoutError("controlled timeout")
    headers = Message()
    headers["Retry-After"] = "1"
    if mode == "nonce":
        headers["DPoP-Nonce"] = nonce
    return urllib.error.HTTPError(
        request.full_url,
        {"rate-limit": 429, "gateway": 502, "nonce": 401}[mode],
        "controlled",
        headers,
        body if body is not None else io.BytesIO(b'{"error":"use_dpop_nonce"}'),
    )


@pytest.mark.parametrize("mode", ["rate-limit", "gateway", "nonce", "timeout"])
@pytest.mark.parametrize("mutate", [False, True])
def test_each_transport_attempt_checks_current_source(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mode: str, mutate: bool
) -> None:
    store, inputs = _store(tmp_path)
    context = _context(store, tmp_path)
    operation = _operation(store, context)
    requests: list[urllib.request.Request] = []
    budgets: list[int] = []
    waits: list[int] = []

    def transport(request: urllib.request.Request, *, timeout: int) -> _Response:
        requests.append(request)
        budgets.append(timeout)
        if len(requests) == 1:
            if mutate:
                store.set_sync_payload(authority.INVENTORY_CONTEXT_KEY, _selected(context), NOW)
            raise _error(mode, request)
        return _Response()

    monkeypatch.setattr(runner, "managed_urlopen", transport)
    monkeypatch.setattr(runner, "time", SimpleNamespace(**{**vars(time), "sleep": waits.append}))

    def call() -> dict[str, object]:
        return runner._urlopen_json_with_timeout_retry(
            request=_request(inputs),
            timeout_seconds=90,
            retry_timeout_seconds=120,
            validate_request=lambda: authority.require_current_aibom_operation(store, operation),
        )

    if mutate:
        with pytest.raises(RuntimeError, match="context changed"):
            call()
        assert budgets == [90]
        assert waits == []
    else:
        assert call() == {"accepted": 1}
        assert budgets == [90, 120 if mode == "timeout" else 90]
        assert waits == ([1] if mode in {"rate-limit", "gateway"} else [])
        assert requests[0].get_header("Dpop") != requests[1].get_header("Dpop")


@pytest.mark.parametrize("mode", ["rate-limit", "gateway"])
def test_change_during_existing_wait_prevents_next_attempt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mode: str
) -> None:
    store, inputs = _store(tmp_path)
    context = _context(store, tmp_path)
    operation = _operation(store, context)
    requests: list[object] = []
    waits: list[int] = []

    def transport(request: urllib.request.Request, *, timeout: int) -> _Response:
        assert timeout == 90
        requests.append(request)
        raise _error(mode, request)

    def wait(seconds: int) -> None:
        waits.append(seconds)
        store.set_sync_payload(authority.INVENTORY_CONTEXT_KEY, _selected(context), NOW)

    monkeypatch.setattr(runner, "managed_urlopen", transport)
    monkeypatch.setattr(runner, "time", SimpleNamespace(**{**vars(time), "sleep": wait}))
    with pytest.raises(RuntimeError, match="context changed"):
        runner._urlopen_json_with_timeout_retry(
            request=_request(inputs),
            timeout_seconds=90,
            retry_timeout_seconds=120,
            validate_request=lambda: authority.require_current_aibom_operation(store, operation),
        )
    assert len(requests) == 1
    assert waits == [1]


@pytest.mark.parametrize("boundary", ["read", "exit", "error-read"])
def test_completed_response_cannot_outlive_captured_authority(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, boundary: str
) -> None:
    store, inputs = _store(tmp_path)
    context = _context(store, tmp_path)
    operation = _operation(store, context)
    requests: list[object] = []

    def mutate() -> None:
        store.set_sync_payload(authority.INVENTORY_CONTEXT_KEY, _selected(context), NOW)

    def transport(request: urllib.request.Request, *, timeout: int) -> _Response:
        assert timeout == 90
        requests.append(request)
        if boundary == "error-read":
            raise _error("nonce", request, _Response(read_action=mutate))
        return _Response(
            read_action=mutate if boundary == "read" else None, exit_action=mutate if boundary == "exit" else None
        )

    monkeypatch.setattr(runner, "managed_urlopen", transport)
    with pytest.raises(RuntimeError, match="context changed"):
        runner._urlopen_json_with_timeout_retry(
            request=_request(inputs),
            timeout_seconds=90,
            retry_timeout_seconds=120,
            validate_request=lambda: authority.require_current_aibom_operation(store, operation),
        )
    assert len(requests) == 1


@pytest.mark.parametrize("after_response", [False, True])
def test_local_validator_oserror_is_not_a_network_retry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, after_response: bool
) -> None:
    _store_value, inputs = _store(tmp_path)
    requests: list[object] = []
    checks: list[object] = []

    def validate() -> None:
        checks.append(None)
        if not after_response or requests:
            raise TimeoutError("controlled local check failure")

    def transport(request: urllib.request.Request, *, timeout: int) -> _Response:
        assert timeout == 90
        requests.append(request)
        return _Response()

    monkeypatch.setattr(runner, "managed_urlopen", transport)
    with pytest.raises(TimeoutError, match="local check"):
        runner._urlopen_json_with_timeout_retry(
            request=_request(inputs),
            timeout_seconds=90,
            retry_timeout_seconds=120,
            validate_request=validate,
        )
    assert len(requests) == int(after_response)
    assert len(checks) == 1 + int(after_response)


@pytest.mark.parametrize("mode", ["rate-limit", "gateway", "nonce", "timeout"])
def test_original_retry_counts_and_budgets_are_preserved(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mode: str
) -> None:
    store, inputs = _store(tmp_path)
    operation = _operation(store, _context(store, tmp_path))
    budgets: list[int] = []
    waits: list[int] = []

    def transport(request: urllib.request.Request, *, timeout: int) -> _Response:
        budgets.append(timeout)
        raise _error(mode, request, nonce=f"controlled-nonce-{len(budgets)}")

    monkeypatch.setattr(runner, "managed_urlopen", transport)
    monkeypatch.setattr(runner, "time", SimpleNamespace(**{**vars(time), "sleep": waits.append}))
    with pytest.raises(OSError):
        runner._urlopen_json_with_timeout_retry(
            request=_request(inputs),
            timeout_seconds=90,
            retry_timeout_seconds=120,
            validate_request=lambda: authority.require_current_aibom_operation(store, operation),
        )
    assert budgets == {"rate-limit": [90] * 3, "gateway": [90] * 3, "nonce": [90] * 4, "timeout": [90, 120]}[mode]
    assert waits == ([1, 1] if mode in {"rate-limit", "gateway"} else [])


def test_repeated_identical_nonce_retains_its_existing_early_refusal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, inputs = _store(tmp_path)
    operation = _operation(store, _context(store, tmp_path))
    budgets: list[int] = []

    def transport(request: urllib.request.Request, *, timeout: int) -> _Response:
        budgets.append(timeout)
        raise _error("nonce", request)

    monkeypatch.setattr(runner, "managed_urlopen", transport)
    with pytest.raises(urllib.error.HTTPError):
        runner._urlopen_json_with_timeout_retry(
            request=_request(inputs),
            timeout_seconds=90,
            retry_timeout_seconds=120,
            validate_request=lambda: authority.require_current_aibom_operation(store, operation),
        )
    assert budgets == [90, 90]


@pytest.mark.parametrize("body", [b"{malformed", b"\xff", b"[]"])
@pytest.mark.parametrize("mutate", [False, True])
def test_completed_invalid_response_still_checks_current_operation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, body: bytes, mutate: bool
) -> None:
    store, inputs = _store(tmp_path)
    context = _context(store, tmp_path)
    operation = _operation(store, context)
    requests: list[object] = []

    class InvalidResponse(io.BytesIO):
        def read(self, size: int | None = -1) -> bytes:
            value = super().read(size)
            if mutate:
                store.set_sync_payload(authority.INVENTORY_CONTEXT_KEY, _selected(context), NOW)
            return value

    def transport(request: object, *, timeout: int) -> InvalidResponse:
        assert timeout == 90
        requests.append(request)
        return InvalidResponse(body)

    monkeypatch.setattr(runner, "managed_urlopen", transport)
    with pytest.raises(
        RuntimeError if mutate else (ValueError, RuntimeError), match="context changed" if mutate else None
    ):
        runner._urlopen_json_with_timeout_retry(
            request=_request(inputs),
            timeout_seconds=90,
            retry_timeout_seconds=120,
            validate_request=lambda: authority.require_current_aibom_operation(store, operation),
        )
    assert len(requests) == 1
