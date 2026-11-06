"""Guard's requests sessions refuse content-encoded responses before any decoder runs."""

from __future__ import annotations

import gzip
import threading
import zlib
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import ClassVar

import pytest
import requests
import urllib3.response

from codex_plugin_scanner.guard.bridge import _DAEMON_SESSION
from codex_plugin_scanner.guard.mdm.contracts import ManagedNetworkPolicy
from codex_plugin_scanner.guard.mdm.network_transport import (
    EncodedResponseRefusedError,
    managed_requests_session,
    refuse_encoded_responses,
)

BODY = b'{"items": []}'
# Bytes are what a server would send; a Brotli or zstd payload need not be valid,
# because nothing may try to decode it.
RESPONSES: dict[str, tuple[str | None, bytes]] = {
    "/plain": (None, BODY),
    "/identity": ("identity", BODY),
    "/gzip": ("gzip", gzip.compress(BODY)),
    "/deflate": ("deflate", zlib.compress(BODY)),
    "/br": ("br", b"\x8b\x06\x80" + BODY + b"\x03"),
    "/zstd": ("zstd", b"\x28\xb5\x2f\xfd" + BODY),
    "/layered": ("identity, gzip", gzip.compress(BODY)),
    "/upper": ("GZIP", gzip.compress(BODY)),
    "/unknown": ("x-guard-test", BODY),
    "/redirect-to-gzip": (None, b""),
}


class _Handler(BaseHTTPRequestHandler):
    accept_encodings: ClassVar[list[str | None]] = []

    def do_GET(self) -> None:
        self.accept_encodings.append(self.headers.get("Accept-Encoding"))
        if self.path == "/redirect-to-gzip":
            self.send_response(302)
            self.send_header("Location", "/gzip")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        encoding, payload = RESPONSES[self.path]
        self.send_response(200)
        if encoding is not None:
            self.send_header("Content-Encoding", encoding)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        return


@pytest.fixture
def origin() -> Iterator[str]:
    _Handler.accept_encodings = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()


@pytest.fixture
def decoder_calls(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    calls: list[str] = []
    real = urllib3.response._get_decoder

    def counting(mode: str):  # type: ignore[no-untyped-def]
        calls.append(mode)
        return real(mode)

    monkeypatch.setattr(urllib3.response, "_get_decoder", counting)
    return calls


def _sessions() -> list[tuple[str, requests.Session]]:
    return [
        ("managed", managed_requests_session(ManagedNetworkPolicy(proxy_mode="none"))),
        ("daemon", _DAEMON_SESSION),
    ]


@pytest.mark.parametrize("path", ["/gzip", "/deflate", "/br", "/zstd", "/layered", "/upper", "/unknown"])
def test_encoded_responses_are_refused_before_any_decoder(origin: str, decoder_calls: list[str], path: str) -> None:
    for name, session in _sessions():
        with pytest.raises(EncodedResponseRefusedError, match="managed_response_content_encoding_refused"):
            session.get(origin + path, timeout=5)
        assert decoder_calls == [], name


def test_redirect_to_an_encoded_response_is_refused_before_decode(origin: str, decoder_calls: list[str]) -> None:
    for _name, session in _sessions():
        with pytest.raises(EncodedResponseRefusedError):
            session.get(origin + "/redirect-to-gzip", timeout=5)
    assert decoder_calls == []


@pytest.mark.parametrize("path", ["/plain", "/identity"])
def test_identity_responses_are_read_unchanged(origin: str, decoder_calls: list[str], path: str) -> None:
    for name, session in _sessions():
        response = session.get(origin + path, timeout=5)
        assert response.status_code == 200, name
        assert response.json() == {"items": []}, name
    assert decoder_calls == []


def test_sessions_ask_for_identity_only(origin: str) -> None:
    for _name, session in _sessions():
        session.get(origin + "/plain", timeout=5)
    assert _Handler.accept_encodings == ["identity", "identity"]


def test_a_plain_session_still_decodes_so_the_counter_is_live(origin: str, decoder_calls: list[str]) -> None:
    response = requests.Session().get(origin + "/gzip", timeout=5)
    assert response.json() == {"items": []}
    assert decoder_calls == ["gzip"]


def test_refusal_is_reusable_on_any_session(origin: str, decoder_calls: list[str]) -> None:
    session = refuse_encoded_responses(requests.Session())
    session.trust_env = False
    with pytest.raises(EncodedResponseRefusedError):
        session.get(origin + "/br", timeout=5)
    assert decoder_calls == []


def _read_body(response: requests.Response, *args: object, **kwargs: object) -> None:
    _ = response.content


def test_refusal_runs_before_hooks_registered_earlier(origin: str, decoder_calls: list[str]) -> None:
    session = requests.Session()
    session.trust_env = False
    session.hooks["response"].append(_read_body)
    refuse_encoded_responses(session)
    with pytest.raises(EncodedResponseRefusedError):
        session.get(origin + "/gzip", timeout=5)
    assert decoder_calls == []
