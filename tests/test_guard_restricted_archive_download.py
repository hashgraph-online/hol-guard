"""Security regressions for approved external archive downloads."""

from __future__ import annotations

import hashlib
import io
import socket
import ssl
import stat
import time
from pathlib import Path
from typing import cast

import pytest

from codex_plugin_scanner.guard.runtime import restricted_archive_download as downloader
from codex_plugin_scanner.guard.runtime.restricted_archive_download import (
    RestrictedArchiveDownload,
    RestrictedArchiveFailure,
    download_restricted_archive,
)


class _FakeResponse:
    def __init__(self, status: int, body: bytes = b"", *, headers: dict[str, str] | None = None) -> None:
        self.status = status
        self.headers = headers or {}
        self._body = io.BytesIO(body)
        self.closed = False
        self.timeouts: list[float] = []

    def read(self, amount: int = -1) -> bytes:
        return self._body.read(amount)

    def get_header(self, name: str) -> str | None:
        return next((value for key, value in self.headers.items() if key.lower() == name.lower()), None)

    def header_items(self) -> tuple[tuple[str, str], ...]:
        return tuple(self.headers.items())

    def set_timeout(self, timeout: float) -> None:
        self.timeouts.append(timeout)

    def close(self) -> None:
        self.closed = True


def _public_dns(*_args: object, **_kwargs: object) -> list[tuple[object, ...]]:
    return [
        (
            socket.AF_INET,
            socket.SOCK_STREAM,
            socket.IPPROTO_TCP,
            "",
            ("93.184.216.34", 443),
        )
    ]


def test_restricted_archive_download_rejects_loopback_redirect_before_connection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    opened_destinations: list[str] = []
    first_response = _FakeResponse(
        302,
        headers={"Location": "https://127.0.0.1/latest/meta-data/archive.tgz"},
    )
    monkeypatch.setattr(downloader.socket, "getaddrinfo", _public_dns)

    def fake_open(destination: object, _address: str, *, deadline: float) -> _FakeResponse:
        assert deadline > 0
        opened_destinations.append(cast(downloader._CanonicalDestination, destination).url)
        return first_response

    monkeypatch.setattr(downloader, "_open_pinned_https_response", fake_open)

    result = download_restricted_archive(
        "https://packages.example.com/archive.tgz",
        temp_dir=tmp_path,
    )

    assert isinstance(result, RestrictedArchiveFailure)
    assert result.code == "external_archive_destination_rejected"
    assert opened_destinations == ["https://packages.example.com/archive.tgz"]
    assert first_response.closed is True
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize(
    "source_url",
    (
        "https://faß.example/archive.tgz",
        "https://packages。example.com/archive.tgz",
    ),
)
def test_restricted_archive_download_rejects_ambiguous_unicode_hostname_before_dns(
    source_url: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    dns_calls: list[str] = []

    def unexpected_dns(hostname: str, *_args: object, **_kwargs: object) -> list[tuple[object, ...]]:
        dns_calls.append(hostname)
        return _public_dns()

    monkeypatch.setattr(downloader.socket, "getaddrinfo", unexpected_dns)

    result = download_restricted_archive(source_url, temp_dir=tmp_path)

    assert isinstance(result, RestrictedArchiveFailure)
    assert result.code == "external_archive_destination_rejected"
    assert dns_calls == []
    assert list(tmp_path.iterdir()) == []


def test_restricted_archive_download_accepts_bounded_public_https_archive(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    archive = b"bounded public HTTPS archive fixture"
    response = _FakeResponse(200, archive, headers={"Content-Length": str(len(archive))})
    monkeypatch.setattr(downloader.socket, "getaddrinfo", _public_dns)
    monkeypatch.setattr(
        downloader,
        "_open_pinned_https_response",
        lambda *_args, **_kwargs: response,
    )

    result = download_restricted_archive(
        "https://packages.example.com/releases/archive.tgz?channel=stable",
        temp_dir=tmp_path,
    )

    assert isinstance(result, RestrictedArchiveDownload)
    assert result.path.read_bytes() == archive
    assert result.sha256 == hashlib.sha256(archive).hexdigest()
    assert result.size == len(archive)
    assert result.final_url == "https://packages.example.com/releases/archive.tgz?channel=stable"
    assert "channel=stable" not in repr(result)
    assert stat.S_IMODE(result.path.stat().st_mode) & (stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH) == 0
    assert response.closed is True
    result.cleanup()
    assert list(tmp_path.iterdir()) == []


def test_restricted_archive_download_rejects_mixed_public_private_dns_answers(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def mixed_dns(*_args: object, **_kwargs: object) -> list[tuple[object, ...]]:
        return [
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("93.184.216.34", 443)),
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("10.0.0.8", 443)),
        ]

    monkeypatch.setattr(downloader.socket, "getaddrinfo", mixed_dns)
    monkeypatch.setattr(
        downloader,
        "_open_pinned_https_response",
        lambda *_args, **_kwargs: pytest.fail("mixed DNS response reached transport"),
    )

    result = download_restricted_archive("https://packages.example.com/archive.tgz", temp_dir=tmp_path)

    assert isinstance(result, RestrictedArchiveFailure)
    assert result.code == "external_archive_dns_ambiguous"
    assert list(tmp_path.iterdir()) == []


def test_restricted_archive_download_rejects_peer_outside_validated_dns_set(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class ReboundSocket:
        def getpeername(self) -> tuple[str, int]:
            return "127.0.0.1", 443

        def close(self) -> None:
            return None

    monkeypatch.setattr(downloader.socket, "getaddrinfo", _public_dns)
    monkeypatch.setattr(
        downloader.socket,
        "create_connection",
        lambda *_args, **_kwargs: ReboundSocket(),
    )

    result = download_restricted_archive("https://packages.example.com/archive.tgz", temp_dir=tmp_path)

    assert isinstance(result, RestrictedArchiveFailure)
    assert result.code == "external_archive_dns_rebinding"
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize(
    "source_url",
    (
        "http://packages.example.com/archive.tgz",
        "https://user:secret@packages.example.com/archive.tgz",
        "https://127.0.0.1/archive.tgz",
        "https://169.254.169.254/latest/meta-data/archive.tgz",
        "https://[::ffff:127.0.0.1]/archive.tgz",
    ),
)
def test_restricted_archive_download_rejects_non_public_or_credentialed_destinations(
    tmp_path: Path,
    source_url: str,
) -> None:
    result = download_restricted_archive(source_url, temp_dir=tmp_path)

    assert isinstance(result, RestrictedArchiveFailure)
    assert result.code == "external_archive_destination_rejected"
    assert list(tmp_path.iterdir()) == []


def test_restricted_archive_download_fails_closed_on_truncated_response(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    response = _FakeResponse(200, b"short", headers={"Content-Length": "20"})
    monkeypatch.setattr(downloader.socket, "getaddrinfo", _public_dns)
    monkeypatch.setattr(
        downloader,
        "_open_pinned_https_response",
        lambda *_args, **_kwargs: response,
    )

    result = download_restricted_archive("https://packages.example.com/archive.tgz", temp_dir=tmp_path)

    assert isinstance(result, RestrictedArchiveFailure)
    assert result.code == "external_archive_incomplete_response"
    assert response.closed is True
    assert list(tmp_path.iterdir()) == []


def test_restricted_archive_download_enforces_streamed_size_limit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    response = _FakeResponse(200, b"12345")
    monkeypatch.setattr(downloader.socket, "getaddrinfo", _public_dns)
    monkeypatch.setattr(
        downloader,
        "_open_pinned_https_response",
        lambda *_args, **_kwargs: response,
    )

    result = download_restricted_archive(
        "https://packages.example.com/archive.tgz",
        max_bytes=4,
        temp_dir=tmp_path,
    )

    assert isinstance(result, RestrictedArchiveFailure)
    assert result.code == "external_archive_download_size_limit"
    assert response.closed is True
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize(
    "redirect_location",
    (
        "http://packages.example.com/archive.tgz",
        "https://user:secret@packages.example.com/archive.tgz",
    ),
)
def test_restricted_archive_download_rejects_non_https_or_credentialed_redirect(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    redirect_location: str,
) -> None:
    response = _FakeResponse(302, headers={"Location": redirect_location})
    monkeypatch.setattr(downloader.socket, "getaddrinfo", _public_dns)
    monkeypatch.setattr(downloader, "_open_pinned_https_response", lambda *_args, **_kwargs: response)

    result = download_restricted_archive("https://packages.example.com/archive.tgz", temp_dir=tmp_path)

    assert isinstance(result, RestrictedArchiveFailure)
    assert result.code == "external_archive_redirect_rejected"
    assert response.closed is True
    assert list(tmp_path.iterdir()) == []


def test_restricted_archive_download_enforces_redirect_limit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    responses: list[_FakeResponse] = []
    monkeypatch.setattr(downloader.socket, "getaddrinfo", _public_dns)

    def redirect(*_args: object, **_kwargs: object) -> _FakeResponse:
        response = _FakeResponse(302, headers={"Location": "/archive.tgz"})
        responses.append(response)
        return response

    monkeypatch.setattr(downloader, "_open_pinned_https_response", redirect)

    result = download_restricted_archive(
        "https://packages.example.com/archive.tgz",
        max_redirects=2,
        temp_dir=tmp_path,
    )

    assert isinstance(result, RestrictedArchiveFailure)
    assert result.code == "external_archive_redirect_limit"
    assert len(responses) == 3
    assert all(response.closed for response in responses)


def test_restricted_archive_download_rejects_declared_oversized_body(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    response = _FakeResponse(200, headers={"Content-Length": "5"})
    monkeypatch.setattr(downloader.socket, "getaddrinfo", _public_dns)
    monkeypatch.setattr(downloader, "_open_pinned_https_response", lambda *_args, **_kwargs: response)

    result = download_restricted_archive(
        "https://packages.example.com/archive.tgz",
        max_bytes=4,
        temp_dir=tmp_path,
    )

    assert isinstance(result, RestrictedArchiveFailure)
    assert result.code == "external_archive_download_size_limit"
    assert response.closed is True


def test_restricted_archive_download_fails_closed_on_slow_body(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class SlowResponse(_FakeResponse):
        def read(self, amount: int = -1) -> bytes:
            del amount
            raise TimeoutError

    response = SlowResponse(200)
    monkeypatch.setattr(downloader.socket, "getaddrinfo", _public_dns)
    monkeypatch.setattr(downloader, "_open_pinned_https_response", lambda *_args, **_kwargs: response)

    result = download_restricted_archive("https://packages.example.com/archive.tgz", temp_dir=tmp_path)

    assert isinstance(result, RestrictedArchiveFailure)
    assert result.code == "external_archive_download_timeout"
    assert response.closed is True
    assert list(tmp_path.iterdir()) == []


def test_restricted_archive_download_enforces_deadline_while_writing_blob(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    response = _FakeResponse(200, body=b"archive bytes")
    real_write = downloader.os.write

    def slow_write(file_descriptor: int, payload: bytes | memoryview) -> int:
        time.sleep(0.25)
        return real_write(file_descriptor, payload)

    monkeypatch.setattr(downloader.socket, "getaddrinfo", _public_dns)
    monkeypatch.setattr(downloader, "_open_pinned_https_response", lambda *_args, **_kwargs: response)
    monkeypatch.setattr(downloader.os, "write", slow_write)

    started = time.monotonic()
    result = download_restricted_archive(
        "https://packages.example.com/archive.tgz",
        timeout_seconds=0.03,
        temp_dir=tmp_path,
    )
    elapsed = time.monotonic() - started

    assert isinstance(result, RestrictedArchiveFailure)
    assert result.code == "external_archive_download_timeout"
    assert elapsed < 0.15
    assert list(tmp_path.iterdir()) == []


def test_restricted_archive_download_rejects_oversized_response_headers(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    headers = {f"X-Fixture-{index}": "value" for index in range(65)}
    response = _FakeResponse(200, headers=headers)
    monkeypatch.setattr(downloader.socket, "getaddrinfo", _public_dns)
    monkeypatch.setattr(downloader, "_open_pinned_https_response", lambda *_args, **_kwargs: response)

    result = download_restricted_archive("https://packages.example.com/archive.tgz", temp_dir=tmp_path)

    assert isinstance(result, RestrictedArchiveFailure)
    assert result.code == "external_archive_response_headers_invalid"
    assert response.closed is True
    assert list(tmp_path.iterdir()) == []


def test_restricted_archive_download_reports_tls_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(downloader.socket, "getaddrinfo", _public_dns)

    def tls_failure(*_args: object, **_kwargs: object) -> _FakeResponse:
        raise ssl.SSLError("controlled TLS fixture")

    monkeypatch.setattr(downloader, "_open_pinned_https_response", tls_failure)

    result = download_restricted_archive("https://packages.example.com/archive.tgz", temp_dir=tmp_path)

    assert isinstance(result, RestrictedArchiveFailure)
    assert result.code == "external_archive_tls_error"
    assert list(tmp_path.iterdir()) == []


def test_restricted_archive_download_enforces_one_absolute_deadline_during_headers(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class RawSocket:
        def getpeername(self) -> tuple[str, int]:
            return "93.184.216.34", 443

        def close(self) -> None:
            return None

    class TLSSocket:
        def getpeername(self) -> tuple[str, int]:
            return "93.184.216.34", 443

        def sendall(self, _payload: bytes) -> None:
            return None

        def settimeout(self, _timeout: float) -> None:
            return None

        def close(self) -> None:
            return None

    tls_socket = TLSSocket()

    class TLSContext:
        def wrap_socket(self, _raw_socket: object, *, server_hostname: str) -> TLSSocket:
            assert server_hostname == "packages.example.com"
            return tls_socket

    class SlowHTTPResponse:
        status = 200

        def __init__(self, _socket: object) -> None:
            return None

        def begin(self) -> None:
            time.sleep(0.25)

        def close(self) -> None:
            return None

    monkeypatch.setattr(downloader.socket, "getaddrinfo", _public_dns)
    monkeypatch.setattr(downloader.socket, "create_connection", lambda *_args, **_kwargs: RawSocket())
    monkeypatch.setattr(downloader, "managed_ssl_context", TLSContext)
    monkeypatch.setattr(downloader.http.client, "HTTPResponse", SlowHTTPResponse)

    started = time.monotonic()
    result = download_restricted_archive(
        "https://packages.example.com/archive.tgz",
        timeout_seconds=0.03,
        temp_dir=tmp_path,
    )
    elapsed = time.monotonic() - started

    assert isinstance(result, RestrictedArchiveFailure)
    assert result.code == "external_archive_download_timeout"
    assert elapsed < 0.15
    assert list(tmp_path.iterdir()) == []


def test_restricted_archive_download_ignores_ambient_proxy_and_authorization(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    created_targets: list[tuple[str, int]] = []

    class RawSocket:
        def getpeername(self) -> tuple[str, int]:
            return "93.184.216.34", 443

        def close(self) -> None:
            return None

    class TLSSocket:
        def __init__(self) -> None:
            self.request = b""
            self.server_hostname: str | None = None

        def getpeername(self) -> tuple[str, int]:
            return "93.184.216.34", 443

        def sendall(self, payload: bytes) -> None:
            self.request += payload

        def settimeout(self, _timeout: float) -> None:
            return None

        def close(self) -> None:
            return None

    tls_socket = TLSSocket()

    class TLSContext:
        def wrap_socket(self, _raw_socket: object, *, server_hostname: str) -> TLSSocket:
            tls_socket.server_hostname = server_hostname
            return tls_socket

    class HTTPResponse:
        status = 200

        def __init__(self, _socket: object) -> None:
            return None

        def begin(self) -> None:
            return None

        def getheaders(self) -> list[tuple[str, str]]:
            return [("Content-Length", "0")]

        def getheader(self, name: str) -> str | None:
            return "0" if name.lower() == "content-length" else None

        def read(self, _amount: int = -1) -> bytes:
            return b""

        def read1(self, _amount: int = -1) -> bytes:
            return b""

        def close(self) -> None:
            return None

    def create_connection(target: tuple[str, int], *, timeout: float) -> RawSocket:
        assert timeout > 0
        created_targets.append(target)
        return RawSocket()

    monkeypatch.setenv("HTTPS_PROXY", "http://proxy-user:proxy-secret@127.0.0.1:9999")
    monkeypatch.setenv("HTTP_PROXY", "http://proxy-user:proxy-secret@127.0.0.1:9999")
    monkeypatch.setattr(downloader.socket, "getaddrinfo", _public_dns)
    monkeypatch.setattr(downloader.socket, "create_connection", create_connection)
    monkeypatch.setattr(downloader, "managed_ssl_context", TLSContext)
    monkeypatch.setattr(downloader.http.client, "HTTPResponse", HTTPResponse)

    result = download_restricted_archive("https://packages.example.com/archive.tgz", temp_dir=tmp_path)

    assert isinstance(result, RestrictedArchiveDownload)
    request = tls_socket.request.decode("ascii")
    assert created_targets == [("93.184.216.34", 443)]
    assert tls_socket.server_hostname == "packages.example.com"
    assert "Authorization:" not in request
    assert "Proxy-Authorization:" not in request
    assert "Cookie:" not in request
    result.cleanup()
