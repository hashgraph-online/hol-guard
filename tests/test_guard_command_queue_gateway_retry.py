"""Command queue requests go through the native Guard Cloud request.

The native runtime pauses briefly before a gateway retry, so a lease, ack or
result is retried quickly rather than after the minute a sync waits.
"""

from __future__ import annotations

import pytest

from codex_plugin_scanner.guard.runtime import cloud_bundle_sync, command_queue_http

_AUTH = {"sync_url": "https://cloud.example.test/api/guard/receipts/sync"}


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
