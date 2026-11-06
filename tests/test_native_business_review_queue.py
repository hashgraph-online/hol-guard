"""Native discovery presentation checks, not provider journey qualification."""

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.runtime import native_business_review_queue as adapter
from tests.test_native_business_review_summary import summary


@pytest.fixture
def resident(monkeypatch):
    monkeypatch.setattr(
        adapter,
        "native_runtime_status",
        lambda: SimpleNamespace(
            available=True,
            compatible=True,
            identity=SimpleNamespace(path=Path("/test/native")),
            capabilities=SimpleNamespace(features=("resident-protocol-v2", "native-local-business-review-queue-v1")),
        ),
    )
    monkeypatch.setattr(adapter, "_isolated_environment", lambda: {})
    calls = []

    def install(response):
        def request(**kwargs):
            calls.append(kwargs)
            return response

        monkeypatch.setattr(adapter, "native_resident_client_request", request)

    return install, calls


def wire(items):
    return json.dumps({"schema": "guard-native-local-business-review-queue.v1", "version": 1, "items": items}).encode()


def test_discovery_sends_no_selectors_or_content_and_never_stages(tmp_path, resident):
    install, calls = resident
    install(wire([summary()]))
    assert adapter.read_native_business_review_queue(tmp_path) == [summary()]
    assert json.loads(calls[0]["payload"]) == {"operation": "workspace_review_local_queue", "request": {}}
    assert calls[0]["timeout_seconds"] == 2.0
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize(
    "response",
    [
        None,
        b"{",
        b'"invalid"',
        b'{"error":"native_local_business_queue_unavailable"}',
        b'{"error":"native_workspace_review_origin_invalid"}',
        wire([summary(), summary()]),
        wire([{**summary(), "request_id": "../escape"}]),
        wire([{**summary(), "subject": "PRIVATE_CANARY"}]),
        wire([summary()] * 129),
        wire([{**summary(), "request_id": "z"}, {**summary(), "request_id": "a"}]),
    ],
)
def test_failed_or_malformed_native_discovery_cannot_be_an_empty_queue(tmp_path, resident, response):
    resident[0](response)
    with pytest.raises(adapter.NativeBusinessReviewQueueReadError, match=r"^native_local_business_queue_read_failed$"):
        adapter.read_native_business_review_queue(tmp_path)


@pytest.mark.parametrize("code", ["native_policy_snapshot_missing", "native_policy_snapshot_unavailable"])
def test_missing_policy_is_optional_absence(tmp_path, resident, code):
    resident[0](json.dumps({"error": code, "retryable": False}).encode())
    assert adapter.read_native_business_review_queue(tmp_path) == []


def test_unavailable_native_does_not_connect(tmp_path, monkeypatch):
    monkeypatch.setattr(adapter, "native_runtime_status", lambda: SimpleNamespace(available=False))

    def unexpected(**kwargs):
        pytest.fail("unavailable runtime must not connect")

    monkeypatch.setattr(adapter, "native_resident_client_request", unexpected)
    assert adapter.read_native_business_review_queue(tmp_path) == []
