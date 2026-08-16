from __future__ import annotations

import ssl
import urllib.error
import urllib.request
from datetime import datetime, timezone
from email.utils import format_datetime
from types import SimpleNamespace

import pytest
from urllib3.exceptions import MaxRetryError
from urllib3.exceptions import SSLError as Urllib3SSLError

from codex_plugin_scanner.guard.mdm import network_diagnostics as diagnostics_module
from codex_plugin_scanner.guard.mdm import network_transport as transport_module
from codex_plugin_scanner.guard.mdm.contracts import ManagedNetworkPolicy
from codex_plugin_scanner.guard.mdm.network_diagnostics import diagnose_endpoint
from codex_plugin_scanner.guard.mdm.network_urlopen import ManagedUrlOpener


class _FakeHTTPResponse:
    status = 401
    reason = "Unauthorized"
    headers = {"Content-Type": "application/json"}

    def __init__(self, body: bytes) -> None:
        self._body = body
        self.closed = False

    def read(self, amt: int | None = None) -> bytes:
        return self._body if amt is None else self._body[:amt]

    def close(self) -> None:
        self.closed = True


class _FakeManagedResponse:
    status = 200

    def __init__(self, headers: dict[str, str]) -> None:
        self.headers = headers

    def __enter__(self) -> _FakeManagedResponse:
        return self

    def __exit__(self, *_args: object) -> None:
        return None


def _proxied_opener(monkeypatch: pytest.MonkeyPatch, request_impl: object) -> ManagedUrlOpener:
    opener = ManagedUrlOpener(
        direct_opener=urllib.request.build_opener(),
        proxy_urls={"https": "https://proxy.example:443"},
        ssl_context=ssl.create_default_context(),
    )
    monkeypatch.setattr(opener, "_manager", lambda _proxy_url: SimpleNamespace(request=request_impl))
    return opener


def test_proxied_http_error_preserves_response_body(monkeypatch: pytest.MonkeyPatch) -> None:
    body = b'{"error":"synthetic"}'
    response = _FakeHTTPResponse(body)

    def request_impl(*_args: object, **_kwargs: object) -> _FakeHTTPResponse:
        return response

    opener = _proxied_opener(monkeypatch, request_impl)

    with pytest.raises(urllib.error.HTTPError) as error:
        opener.open("https://guard.example")

    assert error.value.code == 401
    assert error.value.read() == body
    assert response.closed is True


def test_proxy_response_date_header_drives_clock_diagnostic(monkeypatch: pytest.MonkeyPatch) -> None:
    date_header = format_datetime(datetime.now(timezone.utc), usegmt=True)
    response = _FakeManagedResponse({"date": date_header})
    monkeypatch.setattr(diagnostics_module.socket, "getaddrinfo", lambda *_args, **_kwargs: [(object(),)])
    monkeypatch.setattr(transport_module, "managed_urlopen", lambda *_args, **_kwargs: response)

    result = diagnose_endpoint("https://guard.example", ManagedNetworkPolicy(proxy_mode="none"))

    assert result.reason_code == "endpoint_reachable"
    assert result.clock == "ok"
    assert result.clock_skew_seconds is not None
    assert result.clock_skew_seconds <= 300


def test_proxied_tls_error_remains_classifiable(monkeypatch: pytest.MonkeyPatch) -> None:
    nested = Urllib3SSLError(ssl.SSLCertVerificationError(1, "synthetic certificate detail"))
    failure = MaxRetryError(None, "https://guard.example", reason=nested)

    def request_impl(*_args: object, **_kwargs: object) -> object:
        raise failure

    opener = _proxied_opener(monkeypatch, request_impl)

    with pytest.raises(urllib.error.URLError) as error:
        opener.open("https://guard.example", timeout=5)

    assert isinstance(error.value.reason, ssl.SSLError)
    assert "synthetic certificate detail" not in str(error.value.reason)
