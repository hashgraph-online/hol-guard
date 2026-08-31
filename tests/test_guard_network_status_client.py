from __future__ import annotations

import http.client
import threading
import time
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

    def __enter__(self) -> _RawResponse:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def read(self, _amount: int = -1) -> bytes:
        if self.read_error is not None:
            raise self.read_error
        assert self.payload is not None
        return self.payload


def test_network_status_client_enforces_total_body_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    release_reader = threading.Event()

    class SlowResponse(_RawResponse):
        def read(self, _amount: int = -1) -> bytes:
            release_reader.wait(timeout=2.0)
            return b"{}"

    client = GuardSurfaceDaemonClient("http://127.0.0.1:1", "token")
    monkeypatch.setattr(
        urllib.request,
        "urlopen",
        lambda _request, *, timeout: SlowResponse(payload=b"{}"),
    )
    started_at = time.monotonic()
    try:
        with pytest.raises(GuardDaemonTimeoutError, match="timed out"):
            client.network_status()
    finally:
        release_reader.set()
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
        lambda _request, *, timeout: _RawResponse(
            read_error=http.client.IncompleteRead(b"private partial body", 100)
        ),
    )
    with pytest.raises(GuardDaemonTransportError, match="truncated") as error:
        client.network_status()
    assert "private" not in str(error.value)


@pytest.mark.parametrize("raw_payload", ("not-json", "[]"))
def test_network_status_client_types_invalid_json_object(raw_payload: str) -> None:
    with pytest.raises(GuardDaemonResponseSchemaError):
        GuardSurfaceDaemonClient._decode_json_response(raw_payload)
