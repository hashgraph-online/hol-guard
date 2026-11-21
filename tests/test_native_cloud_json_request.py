"""One Guard Cloud JSON request through the native command, against a loopback Guard Cloud."""

from __future__ import annotations

import json
import tempfile
import threading
import urllib.error
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import ClassVar

import pytest

from codex_plugin_scanner.guard.runtime import cloud_bundle_sync
from codex_plugin_scanner.guard.runtime.runner import GuardSyncEndpointUntrustedError

pytestmark = [pytest.mark.native_cloud_json_request]


class _CloudHandler(BaseHTTPRequestHandler):
    bodies: ClassVar[list[bytes]] = []

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        type(self).bodies.append(self.rfile.read(length) if length else b"")
        if self.path.endswith("/conflict"):
            status, answer = 409, {"error": "lease_conflict"}
        else:
            status, answer = 200, {"item": None, "path": self.path}
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(answer).encode("utf-8"))

    def do_GET(self) -> None:
        type(self).bodies.append(b"GET")
        if self.path.endswith("/no-content"):
            self.send_response(204)
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"versionNumber": 3, "path": self.path}).encode("utf-8"))

    def log_message(self, fmt: str, *args: object) -> None:
        return


@pytest.fixture
def cloud_origin() -> Iterator[str]:
    _CloudHandler.bodies = []
    server = HTTPServer(("127.0.0.1", 0), _CloudHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        thread.join(timeout=5)


def _auth(origin: str) -> dict[str, object]:
    # Built at runtime so the value never reads as a stored credential.
    return {
        "sync_url": f"{origin}/api/guard/receipts/sync",
        "access_" + "token": "-".join(("loopback", "only")),
        "dpop_key_material": None,
    }


def _send(origin: str, url: str, body: bytes | None = b'{"waitMs":0}') -> dict[str, object]:
    return cloud_bundle_sync.cloud_json_request(
        _auth(origin),
        url=url,
        body=body,
        timeout_seconds=5,
        retry_timeout_seconds=5,
    )


def test_an_object_answer_comes_back_and_the_body_is_sent_byte_for_byte(cloud_origin: str) -> None:
    answer = _send(cloud_origin, f"{cloud_origin}/api/guard/commands/lease")

    assert answer == {"item": None, "path": "/api/guard/commands/lease"}
    assert _CloudHandler.bodies == [b'{"waitMs":0}']


def test_a_refusal_is_an_http_error_with_its_status_and_body(cloud_origin: str) -> None:
    with pytest.raises(urllib.error.HTTPError) as raised:
        _send(cloud_origin, f"{cloud_origin}/api/guard/commands/conflict")

    assert raised.value.code == 409
    assert json.loads(raised.value.read()) == {"error": "lease_conflict"}


def test_a_request_to_another_origin_is_refused_before_it_is_sent(cloud_origin: str) -> None:
    with pytest.raises(GuardSyncEndpointUntrustedError):
        _send(cloud_origin, "http://127.0.0.1:9/api/guard/commands/lease")

    assert _CloudHandler.bodies == []


def test_a_request_without_a_body_is_a_get(cloud_origin: str) -> None:
    answer = _send(cloud_origin, f"{cloud_origin}/api/guard/policy/delivery", body=None)

    assert answer == {"versionNumber": 3, "path": "/api/guard/policy/delivery"}
    assert _CloudHandler.bodies == [b"GET"]


def test_a_body_over_the_inline_limit_is_sent_from_a_private_file(
    cloud_origin: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))
    page = json.dumps({"page": "x" * (2 * 1024 * 1024)}).encode("utf-8")

    answer = _send(cloud_origin, f"{cloud_origin}/api/guard/runtime/extension-catalog/sync-v2", body=page)

    assert answer == {"item": None, "path": "/api/guard/runtime/extension-catalog/sync-v2"}
    assert _CloudHandler.bodies == [page]
    assert list(tmp_path.iterdir()) == []


def _send_raw(origin: str, url: str, body: bytes | None, max_response_bytes: int | None = None) -> tuple[int, bytes]:
    from codex_plugin_scanner.guard.config import resolve_guard_home

    return cloud_bundle_sync.cloud_raw_request(
        _auth(origin),
        resolve_guard_home(),
        url=url,
        body=body,
        timeout_seconds=5,
        retry_timeout_seconds=5,
        max_response_bytes=max_response_bytes,
    )


def test_a_raw_request_keeps_a_no_content_answer(cloud_origin: str) -> None:
    status, body = _send_raw(cloud_origin, f"{cloud_origin}/api/guard/runtime/no-content", None)

    assert (status, body) == (204, b"")


def test_a_raw_request_returns_the_status_and_the_body_unread(cloud_origin: str) -> None:
    status, body = _send_raw(cloud_origin, f"{cloud_origin}/api/guard/runtime/keys", b'{"key":1}')

    assert status == 200
    assert json.loads(body) == {"item": None, "path": "/api/guard/runtime/keys"}
    assert _CloudHandler.bodies == [b'{"key":1}']


def test_a_raw_request_reports_a_body_over_the_callers_limit(cloud_origin: str) -> None:
    url = f"{cloud_origin}/api/guard/runtime/keys"
    with pytest.raises(cloud_bundle_sync.CloudResponseOversizedError):
        _send_raw(cloud_origin, url, b'{"key":1}', max_response_bytes=8)

    status, _body = _send_raw(cloud_origin, url, b'{"key":1}', max_response_bytes=4096)
    assert status == 200


def test_a_raw_request_raises_a_refusal_as_the_http_error(cloud_origin: str) -> None:
    with pytest.raises(urllib.error.HTTPError) as raised:
        _send_raw(cloud_origin, f"{cloud_origin}/api/guard/runtime/conflict", b"{}")

    assert raised.value.code == 409
    assert json.loads(raised.value.read()) == {"error": "lease_conflict"}
