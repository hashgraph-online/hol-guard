"""Guard command acks and results through the native command, against a loopback Guard Cloud."""

from __future__ import annotations

import json
import threading
import urllib.error
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import ClassVar

import pytest

from codex_plugin_scanner.guard.runtime import cloud_command_lease

pytestmark = [pytest.mark.native_command_report]


class _CloudHandler(BaseHTTPRequestHandler):
    sent: ClassVar[list[tuple[str, dict[str, object]]]] = []
    refuse: ClassVar[set[str]] = set()

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        body = json.loads(self.rfile.read(length) or b"{}")
        type(self).sent.append((self.path, body))
        status = 409 if self.path in type(self).refuse else 200
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"ok": status == 200}).encode("utf-8"))

    def log_message(self, fmt: str, *args: object) -> None:
        return


@pytest.fixture
def cloud_origin() -> Iterator[str]:
    _CloudHandler.sent = []
    _CloudHandler.refuse = set()
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


def test_an_exact_ack_and_a_generic_heartbeat_go_to_their_routes(cloud_origin: str) -> None:
    auth = _auth(cloud_origin)

    exact = cloud_command_lease.cloud_command_report(auth, job_id="job-1", exact=True, kind="ack", lease_id="lease-1")
    generic = cloud_command_lease.cloud_command_report(
        auth, job_id="job-2", exact=False, kind="ack", lease_id="lease-2"
    )

    assert exact == {"ok": True}
    assert generic == {"ok": True}
    assert _CloudHandler.sent == [
        ("/api/guard/review/v2/commands/job-1/ack", {"leaseId": "lease-1", "protocolVersion": 2}),
        ("/api/guard/commands/job-2/heartbeat", {"leaseId": "lease-2"}),
    ]


def test_a_result_too_large_for_stdin_is_sent_whole(cloud_origin: str) -> None:
    payload = {"leaseId": "lease-3", "status": "succeeded", "output": "x" * (300 * 1024)}

    cloud_command_lease.cloud_command_report(
        _auth(cloud_origin),
        job_id="job-3",
        exact=False,
        kind="result",
        body=json.dumps(payload, separators=(",", ":")).encode("utf-8"),
    )

    assert _CloudHandler.sent == [("/api/guard/commands/job-3/result", payload)]


def test_a_refused_result_is_raised_against_the_route_it_reached(cloud_origin: str) -> None:
    _CloudHandler.refuse = {"/api/guard/review/v2/commands/job-4/result"}

    with pytest.raises(urllib.error.HTTPError) as raised:
        cloud_command_lease.cloud_command_report(
            _auth(cloud_origin), job_id="job-4", exact=True, kind="result", body=b'{"leaseId":"lease-4"}'
        )

    assert raised.value.code == 409
    assert raised.value.url == f"{cloud_origin}/api/guard/review/v2/commands/job-4/result"


def test_a_job_id_that_leaves_its_path_is_never_sent(cloud_origin: str) -> None:
    with pytest.raises(RuntimeError):
        cloud_command_lease.cloud_command_report(
            _auth(cloud_origin), job_id="../lease", exact=False, kind="ack", lease_id="lease-5"
        )

    assert _CloudHandler.sent == []
