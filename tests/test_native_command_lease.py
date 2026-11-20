"""Guard command leases through the native command, against a loopback Guard Cloud."""

from __future__ import annotations

import json
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import ClassVar

import pytest

from codex_plugin_scanner.guard.runtime import cloud_command_lease
from codex_plugin_scanner.guard.runtime.exact_cloud_review import EXACT_CLOUD_REVIEW_OPERATION
from codex_plugin_scanner.guard.runtime.exact_cloud_review_transport import LeaseCall, lease_next_job

pytestmark = [pytest.mark.native_command_lease]

_GENERIC = "inventory.read"
_EXACT_ROUTE = "/api/guard/review/v2/commands/lease"
_QUEUE_ROUTE = "/api/guard/commands/lease"


def _exact_job(lease: str) -> dict[str, object]:
    return {"id": f"job-{lease}", "leaseId": lease, "protocolVersion": 2}


class _CloudHandler(BaseHTTPRequestHandler):
    sent: ClassVar[list[tuple[str, dict[str, object]]]] = []
    answers: ClassVar[dict[str, dict[str, object]]] = {}

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        body = json.loads(self.rfile.read(length) or b"{}")
        type(self).sent.append((self.path, body))
        answer = type(self).answers.get(self.path, {"item": None})
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(answer).encode("utf-8"))

    def log_message(self, fmt: str, *args: object) -> None:
        return


@pytest.fixture
def cloud_origin() -> Iterator[str]:
    _CloudHandler.sent = []
    _CloudHandler.answers = {}
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


def _lease(origin: str):
    def lease(call: LeaseCall) -> dict[str, object]:
        return cloud_command_lease.cloud_command_lease(
            _auth(origin),
            {
                **call,
                "workspaceId": "workspace-1",
                "deviceId": "device-1",
                "daemonVersion": "1.2.3",
                "schemaVersions": {_GENERIC: 1},
            },
        )

    return lease


def test_an_exact_batch_lease_returns_the_first_job_and_the_extras(cloud_origin: str) -> None:
    _CloudHandler.answers[_EXACT_ROUTE] = {
        "protocolVersion": 2,
        "maxJobs": 4,
        "item": _exact_job("a"),
        "items": [_exact_job("a"), _exact_job("b")],
    }
    extras: list[list[dict[str, object]]] = []
    limits: list[int] = []

    job = lease_next_job(
        operations=(EXACT_CLOUD_REVIEW_OPERATION, _GENERIC),
        wait_ms=25_000,
        lease=_lease(cloud_origin),
        max_jobs=3,
        on_extra_jobs=extras.append,
        observe_lease_batch_limit=limits.append,
    )

    assert job is not None
    assert job["leaseId"] == "a"
    assert [[extra["leaseId"] for extra in batch] for batch in extras] == [["b"]]
    assert limits == [4]
    assert _CloudHandler.sent == [
        (
            _EXACT_ROUTE,
            {
                "workspaceId": "workspace-1",
                "deviceId": "device-1",
                "daemonVersion": "1.2.3",
                "capabilities": {"operations": [EXACT_CLOUD_REVIEW_OPERATION]},
                "maxJobs": 3,
                "waitMs": 0,
                "protocolVersion": 2,
            },
        )
    ]


def test_an_empty_exact_lease_falls_through_to_the_generic_queue(cloud_origin: str) -> None:
    _CloudHandler.answers[_EXACT_ROUTE] = {"protocolVersion": 2, "item": None}
    _CloudHandler.answers[_QUEUE_ROUTE] = {"item": {"id": "job-g", "leaseId": "g"}}
    responses: list[dict[str, object]] = []

    job = lease_next_job(
        operations=(EXACT_CLOUD_REVIEW_OPERATION, _GENERIC),
        wait_ms=25_000,
        lease=_lease(cloud_origin),
        observe_response=responses.append,
    )

    assert job == {"id": "job-g", "leaseId": "g"}
    assert len(responses) == 2
    assert [path for path, _ in _CloudHandler.sent] == [_EXACT_ROUTE, _QUEUE_ROUTE]
    assert _CloudHandler.sent[1][1] == {
        "workspaceId": "workspace-1",
        "deviceId": "device-1",
        "daemonVersion": "1.2.3",
        "capabilities": {"operations": [_GENERIC], "schemaVersions": {_GENERIC: 1}},
        "maxJobs": 1,
        "waitMs": 25_000,
    }


def test_a_generic_lease_error_is_raised_after_the_exact_route_state_is_recorded() -> None:
    from codex_plugin_scanner.guard.runtime.runner import GuardSyncNotAvailableError

    def lease(_call: LeaseCall) -> dict[str, object]:
        return {
            "lease": {
                "exactRoute": "failed",
                "exactRefusal": {"status": 400, "headers": {}, "body": ""},
                "batchLimit": 1,
            },
            "failure": {
                "sync": {
                    "ok": False,
                    "outcome": "not_available",
                    "error": "Guard Cloud is unavailable.",
                    "retryable": True,
                },
                "route": "/api/guard/commands",
            },
        }

    refused: list[int] = []
    limits: list[int] = []
    with pytest.raises(GuardSyncNotAvailableError) as raised:
        lease_next_job(
            operations=(EXACT_CLOUD_REVIEW_OPERATION, _GENERIC),
            wait_ms=0,
            lease=lease,
            exact_route_failure=lambda error: refused.append(error.code),
            observe_lease_batch_limit=limits.append,
        )

    assert raised.value.retryable is True
    assert refused == [400]
    assert limits == [1]
