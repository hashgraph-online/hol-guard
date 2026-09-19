"""Every real retry uses current optional content while retaining the existing retry state."""

from __future__ import annotations

import io
import json
import time
import urllib.error
import urllib.request
from email.message import Message
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.runtime import runner


def _request() -> urllib.request.Request:
    context: dict[str, object] = {
        "sync_url": "https://hol.org/api/guard/receipts/sync",
        "access_token": "synthetic-access",
        "dpop_key_material": None,
    }
    return runner._guard_sync_request(
        context,
        request_url=str(context["sync_url"]),
        method="POST",
        data=b'{"receipts":[{"receiptId":"synthetic"}],"control":true}',
        extra_headers={"X-Controlled": "retained"},
    )


def _error(request: urllib.request.Request, code: int) -> urllib.error.HTTPError:
    headers = Message()
    headers["Retry-After"] = "1"
    if code == 401:
        headers["DPoP-Nonce"] = "controlled-nonce"
    return urllib.error.HTTPError(
        request.full_url,
        code,
        "controlled",
        headers,
        io.BytesIO(b'{"error":"use_dpop_nonce"}' if code == 401 else b"{}"),
    )


@pytest.mark.parametrize("raw", [False, True])
def test_actual_gateway_rate_nonce_and_timeout_retries_prepare_their_own_content(
    monkeypatch: pytest.MonkeyPatch, raw: bool
) -> None:
    prepared: list[urllib.request.Request] = []
    sent: list[urllib.request.Request] = []
    bodies: list[dict[str, object]] = []
    budgets: list[int] = []
    nonces: list[object] = []
    waits: list[float] = []

    def prepare(current: urllib.request.Request) -> None:
        prepared.append(current)
        body = {
            "receipts": [{"receiptId": "synthetic"}] if len(prepared) == 1 else [],
            "control": True,
        }
        current.data = json.dumps(body).encode()

    def transport(current: urllib.request.Request, *, timeout: int) -> io.BytesIO:
        assert prepared[-1] is current
        assert current.get_header("X-controlled") == "retained"
        context = runner._resolve_guard_dpop_retry_context(current)
        assert context is not None
        nonces.append(context["dpop_nonce"])
        sent.append(current)
        assert isinstance(current.data, bytes)
        bodies.append(json.loads(current.data))
        budgets.append(timeout)
        if len(sent) < 4:
            raise _error(current, [502, 429, 401][len(sent) - 1])
        if len(sent) == 4:
            raise TimeoutError("controlled transport timeout")
        return io.BytesIO(b'{"ok":true}')

    monkeypatch.setattr(runner, "managed_urlopen", transport)
    monkeypatch.setattr(runner, "time", SimpleNamespace(**{**vars(time), "sleep": waits.append}))
    request = _request()
    if raw:
        result = runner._urlopen_with_timeout_retry(
            request=request, timeout_seconds=20, retry_timeout_seconds=90, prepare_request=prepare
        )
        assert result is None
    else:
        result = runner._urlopen_json_with_timeout_retry(
            request=request, timeout_seconds=20, retry_timeout_seconds=90, prepare_request=prepare
        )
        assert result == {"ok": True}
    assert sent == prepared
    assert len({id(request) for request in sent}) == 5
    assert budgets == [20, 20, 20, 20, 90]
    assert waits == [1, 1]
    assert nonces == [None, None, None, "controlled-nonce", "controlled-nonce"]
    assert bodies == [
        {"receipts": [{"receiptId": "synthetic"}], "control": True},
        *[{"receipts": [], "control": True} for _ in range(4)],
    ]


@pytest.mark.parametrize("failure", ["timeout", "rate", "value"])
def test_local_preparation_errors_are_not_transport_retries(monkeypatch: pytest.MonkeyPatch, failure: str) -> None:
    request = _request()
    sentinel = (
        TimeoutError("controlled local timeout")
        if failure == "timeout"
        else _error(request, 429)
        if failure == "rate"
        else ValueError("controlled local value")
    )
    sent: list[object] = []
    validated: list[bool] = []
    waits: list[float] = []

    def prepare(_current: urllib.request.Request) -> None:
        raise sentinel

    def transport(*args: object, **_kwargs: object) -> io.BytesIO:
        sent.append(args)
        return io.BytesIO(b"{}")

    monkeypatch.setattr(runner, "managed_urlopen", transport)
    monkeypatch.setattr(runner, "time", SimpleNamespace(**{**vars(time), "sleep": waits.append}))
    with pytest.raises(type(sentinel)) as caught:
        runner._urlopen_json_with_timeout_retry(
            request=request,
            timeout_seconds=20,
            retry_timeout_seconds=90,
            prepare_request=prepare,
            validate_request=lambda: validated.append(True),
        )
    assert caught.value is sentinel
    assert sent == validated == waits == []


def test_existing_validator_still_refuses_the_prepared_attempt_before_transport(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared: list[urllib.request.Request] = []
    sent: list[object] = []
    sentinel = RuntimeError("controlled changed authority")

    def validate() -> None:
        assert len(prepared) == 1
        raise sentinel

    def transport(*args: object, **_kwargs: object) -> io.BytesIO:
        sent.append(args)
        return io.BytesIO(b"{}")

    monkeypatch.setattr(runner, "managed_urlopen", transport)
    with pytest.raises(RuntimeError) as caught:
        runner._urlopen_json_with_timeout_retry(
            request=_request(),
            timeout_seconds=20,
            retry_timeout_seconds=90,
            prepare_request=prepared.append,
            validate_request=validate,
        )
    assert caught.value is sentinel
    assert len(prepared) == 1
    assert sent == []
