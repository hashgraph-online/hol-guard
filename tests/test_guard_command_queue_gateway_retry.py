"""A gateway error on a command queue request is retried after a second, not a minute."""

from __future__ import annotations

import io
import json
import urllib.error
import urllib.request
from contextlib import contextmanager
from email.message import Message

import pytest

from codex_plugin_scanner.guard.runtime import command_queue_http
from codex_plugin_scanner.guard.runtime import runner as runner_module


def _gateway_error(code: int, *, retry_after: str | None = None) -> urllib.error.HTTPError:
    headers = Message()
    if retry_after is not None:
        headers["Retry-After"] = retry_after
    return urllib.error.HTTPError("https://cloud.example.test/lease", code, "Bad Gateway", headers, io.BytesIO(b""))


@pytest.fixture
def transport(monkeypatch: pytest.MonkeyPatch):
    """Answer each request from ``responses`` in turn and record every sleep."""

    responses: list[object] = []
    sleeps: list[float] = []

    @contextmanager
    def fake_urlopen(_request: object, timeout: float):
        answer = responses.pop(0)
        if isinstance(answer, BaseException):
            raise answer
        yield io.BytesIO(json.dumps(answer).encode("utf-8"))

    monkeypatch.setattr(runner_module, "managed_urlopen", fake_urlopen)
    monkeypatch.setattr(runner_module.time, "sleep", sleeps.append)
    monkeypatch.setattr(runner_module, "_refresh_guard_sync_request", lambda _request: None)
    monkeypatch.setattr(
        command_queue_http,
        "_guard_sync_request",
        lambda _auth, *, request_url, method, data: urllib.request.Request(request_url, data=data, method=method),
    )
    return responses, sleeps


def _lease() -> dict[str, object]:
    return command_queue_http.request_json(
        {"sync_url": "https://cloud.example.test/api/guard/receipts/sync"},
        method="POST",
        path="/lease",
        payload={"waitMs": 25000},
    )


@pytest.mark.parametrize("code", [502, 503, 504])
def test_a_lease_whose_server_went_away_is_retried_after_a_second(transport, code: int) -> None:
    responses, sleeps = transport
    responses.extend([_gateway_error(code), {"item": None}])

    assert _lease() == {"item": None}
    # A deploy that replaces the server answers the open lease with a gateway
    # error; waiting the sync default of a minute held every decision made
    # meanwhile for that minute.
    assert sleeps == [1.0]


def test_a_gateway_error_that_names_a_delay_is_still_honored(transport) -> None:
    responses, sleeps = transport
    responses.extend([_gateway_error(503, retry_after="7"), {"item": None}])

    assert _lease() == {"item": None}
    assert sleeps == [7]


def test_a_gateway_error_that_persists_reaches_the_queue_loop_after_its_retries(transport) -> None:
    responses, sleeps = transport
    responses.extend([_gateway_error(502), _gateway_error(502), _gateway_error(502)])

    with pytest.raises(urllib.error.HTTPError):
        _lease()
    assert sleeps == [1.0, 1.0]


def test_other_sync_requests_keep_the_default_gateway_wait(transport) -> None:
    responses, sleeps = transport
    responses.extend([_gateway_error(502), {"ok": True}])

    payload = runner_module._urlopen_json_with_timeout_retry(
        request=urllib.request.Request("https://cloud.example.test/api/guard/receipts/sync", method="POST"),
        timeout_seconds=20,
        retry_timeout_seconds=60,
    )

    assert payload == {"ok": True}
    assert sleeps == [60]
