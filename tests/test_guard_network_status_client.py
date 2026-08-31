from __future__ import annotations

import http.client
import time
import urllib.error
import urllib.request

import pytest

from codex_plugin_scanner.guard.daemon.client import (
    GuardDaemonResponseSchemaError,
    GuardDaemonTimeoutError,
    GuardDaemonTransportError,
    GuardSurfaceDaemonClient,
)
from codex_plugin_scanner.guard.runtime.network_status import build_network_status


def test_network_status_client_uses_fast_status_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = GuardSurfaceDaemonClient("http://127.0.0.1:1", "token")
    observed: dict[str, object] = {}

    def fake_get(path: str, *, timeout: float) -> dict[str, object]:
        observed.update(path=path, timeout=timeout)
        return build_network_status(platform_name="darwin")

    monkeypatch.setattr(client, "_get", fake_get)
    client.network_status()
    assert observed == {"path": "/v1/network/status", "timeout": 0.25}


def test_network_status_client_types_timeout_without_transport_detail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = GuardSurfaceDaemonClient("http://127.0.0.1:1", "token")

    def timeout(_request: urllib.request.Request, *, timeout: float) -> None:
        assert timeout == 0.25
        raise TimeoutError("private operating system detail")

    monkeypatch.setattr(urllib.request, "urlopen", timeout)
    with pytest.raises(GuardDaemonTimeoutError, match="timed out") as error:
        client.network_status()
    assert "private" not in str(error.value)


class _RawResponse:
    def __init__(self, *, payload: bytes | None = None, read_error: Exception | None = None) -> None:
        self.payload = payload
        self.read_error = read_error
        self.read_timeout: float | None = None
        self.consumed = False

    def __enter__(self) -> _RawResponse:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def read(self, _amount: int = -1) -> bytes:
        if self.read_error is not None:
            raise self.read_error
        assert self.payload is not None
        if self.consumed:
            return b""
        self.consumed = True
        return self.payload

    def settimeout(self, timeout: float) -> None:
        self.read_timeout = timeout

    def close(self) -> None:
        return None


def test_network_status_client_enforces_total_body_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class SlowResponse(_RawResponse):
        def read(self, _amount: int = -1) -> bytes:
            assert self.read_timeout is not None
            time.sleep(self.read_timeout)
            raise TimeoutError("private socket timeout")

    client = GuardSurfaceDaemonClient("http://127.0.0.1:1", "token")
    monkeypatch.setattr(
        urllib.request,
        "urlopen",
        lambda _request, *, timeout: SlowResponse(payload=b"{}"),
    )
    started_at = time.monotonic()
    with pytest.raises(GuardDaemonTimeoutError, match="timed out"):
        client.network_status()
    assert time.monotonic() - started_at < 0.75


def test_network_status_client_bounds_http_error_body(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class SlowErrorBody(_RawResponse):
        def read(self, _amount: int = -1) -> bytes:
            assert self.read_timeout is not None
            time.sleep(self.read_timeout)
            raise TimeoutError("private socket timeout")

    error_body = SlowErrorBody(payload=b"{}")

    def raise_http_error(_request: urllib.request.Request, *, timeout: float) -> None:
        raise urllib.error.HTTPError(
            "http://127.0.0.1:1/v1/network/status",
            503,
            "private",
            {},
            error_body,
        )

    client = GuardSurfaceDaemonClient("http://127.0.0.1:1", "token")
    monkeypatch.setattr(urllib.request, "urlopen", raise_http_error)
    started_at = time.monotonic()
    with pytest.raises(GuardDaemonTimeoutError, match="timed out") as error:
        client.network_status()
    assert "private" not in str(error.value)
    assert time.monotonic() - started_at < 0.75


def test_network_status_client_enforces_deadline_across_slow_chunks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class TrickleResponse(_RawResponse):
        def read1(self, _amount: int = -1) -> bytes:
            time.sleep(0.06)
            return b"x"

    client = GuardSurfaceDaemonClient("http://127.0.0.1:1", "token")
    monkeypatch.setattr(
        urllib.request,
        "urlopen",
        lambda _request, *, timeout: TrickleResponse(payload=b"unused"),
    )
    started_at = time.monotonic()
    with pytest.raises(GuardDaemonTimeoutError, match="timed out"):
        client.network_status()
    assert time.monotonic() - started_at < 0.75


def test_network_status_client_types_invalid_utf8_as_schema_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = GuardSurfaceDaemonClient("http://127.0.0.1:1", "token")
    monkeypatch.setattr(
        urllib.request,
        "urlopen",
        lambda _request, *, timeout: _RawResponse(payload=b"\xffprivate"),
    )
    with pytest.raises(GuardDaemonResponseSchemaError) as error:
        client.network_status()
    assert "private" not in str(error.value)


def test_network_status_client_types_truncated_body_as_transport_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = GuardSurfaceDaemonClient("http://127.0.0.1:1", "token")
    monkeypatch.setattr(
        urllib.request,
        "urlopen",
        lambda _request, *, timeout: _RawResponse(read_error=http.client.IncompleteRead(b"private partial body", 100)),
    )
    with pytest.raises(GuardDaemonTransportError, match="truncated") as error:
        client.network_status()
    assert "private" not in str(error.value)


@pytest.mark.parametrize("raw_payload", ("not-json", "[]"))
def test_network_status_client_types_invalid_json_object(raw_payload: str) -> None:
    with pytest.raises(GuardDaemonResponseSchemaError):
        GuardSurfaceDaemonClient._decode_json_response(raw_payload)
