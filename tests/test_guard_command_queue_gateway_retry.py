"""Command queue requests go through the native Guard Cloud request.

The native runtime pauses briefly before a gateway retry, so a lease, ack or
result is retried quickly rather than after the minute a sync waits. The Python
retry machine that other sync requests still use keeps its own waits.
"""

from __future__ import annotations

import io
import json
import urllib.error
import urllib.request
from contextlib import contextmanager
from email.message import Message

import pytest

from codex_plugin_scanner.guard.runtime import cloud_bundle_sync, command_queue_http
from codex_plugin_scanner.guard.runtime import runner as runner_module

_AUTH = {"sync_url": "https://cloud.example.test/api/guard/receipts/sync"}


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
    return responses, sleeps


def test_a_lease_is_one_native_request_with_the_queue_timeouts(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[dict[str, object]] = []

    def native(auth_context, **options):
        calls.append({"auth": auth_context, **options})
        return {"item": None}

    monkeypatch.setattr(cloud_bundle_sync, "cloud_json_request", native)

    answer = command_queue_http.request_json(_AUTH, method="POST", path="/lease", payload={"waitMs": 25000})

    assert answer == {"item": None}
    assert calls == [
        {
            "auth": _AUTH,
            "url": "https://cloud.example.test/api/guard/commands/lease",
            "body": b'{"waitMs":25000}',
            "timeout_seconds": 35,
            "retry_timeout_seconds": 60,
        }
    ]


def test_a_command_queue_request_is_a_post() -> None:
    with pytest.raises(ValueError, match="POST"):
        command_queue_http.request_json(_AUTH, method="GET", path="/lease", payload={})


def test_an_unhinted_gateway_wait_is_honored_by_the_python_retry_machine(transport) -> None:
    responses, sleeps = transport
    responses.extend([_gateway_error(503), {"item": None}])

    payload = runner_module._urlopen_json_with_timeout_retry(
        request=urllib.request.Request("https://cloud.example.test/api/guard/commands/lease", method="POST"),
        timeout_seconds=35,
        retry_timeout_seconds=60,
        unhinted_gateway_retry_seconds=1.0,
    )

    assert payload == {"item": None}
    assert sleeps == [1.0]


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
