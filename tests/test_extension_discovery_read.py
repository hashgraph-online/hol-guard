"""Adapter tests for sponsored extension discovery transport bounds.

These exercise the I/O-only daemon adapter in isolation with a
dependency-injected opener: fixed origin/path, no redirects, bounded reads,
ETag reuse without restamping, coalescing, and the rollout switch. Native
projection is exercised by the Rust vector suite; here the native call is
stubbed at the resident-client boundary.
"""

from __future__ import annotations

import io
import json
import urllib.error
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.daemon import extension_discovery_read as discovery


class FakeResponse(io.BytesIO):
    def __init__(self, body: bytes, status: int = 200, headers: dict[str, str] | None = None) -> None:
        super().__init__(body)
        self.status = status
        self.headers = {"ETag": "", "Date": ""} | (headers or {})


class FakeOpener:
    def __init__(self, responses: list[FakeResponse | urllib.error.HTTPError]) -> None:
        self.responses = list(responses)
        self.requests: list[urllib.request.Request] = []

    def open(self, request: urllib.request.Request, timeout: float) -> FakeResponse:
        self.requests.append(request)
        response = self.responses.pop(0)
        if isinstance(response, urllib.error.HTTPError):
            raise response
        return response


def http_error(code: int) -> urllib.error.HTTPError:
    return urllib.error.HTTPError(
        discovery.DISCOVERY_PLACEMENTS_PATH,
        code,
        "error",
        hdrs=None,
        fp=io.BytesIO(b"{}"),
    )


@pytest.fixture(autouse=True)
def _reset_cache() -> None:
    discovery.reset_discovery_cache_for_tests()
    yield
    discovery.reset_discovery_cache_for_tests()


def snapshot_body(lease_ms: int = 25_000) -> bytes:
    return json.dumps(
        {
            "schemaVersion": "guard.extensions.discovery.v1",
            "snapshotId": "22222222-2222-4222-8222-222222222222",
            "state": "ready",
            "enabled": True,
            "reasonCode": None,
            "generatedAt": "2026-10-13T12:00:00.000Z",
            "leaseExpiresAt": "2026-10-13T12:00:25.000Z",
            "placements": [],
            "offers": [
                {"product": "always", "availability": "unknown", "indicativeAmountCents": None, "currency": None, "checkedAt": None, "quoteRequired": True},
                {"product": "time_slot", "availability": "unknown", "indicativeAmountCents": None, "currency": None, "checkedAt": None, "quoteRequired": True},
                {"product": "sponsored", "availability": "unknown", "indicativeAmountCents": None, "currency": None, "checkedAt": None, "quoteRequired": True},
            ],
        }
    ).encode("utf-8")


def test_fetch_targets_the_fixed_origin_and_path_only() -> None:
    opener = FakeOpener([FakeResponse(snapshot_body(), headers={"Date": "Mon, 13 Oct 2026 12:00:02 GMT"})])
    cached = discovery.fetch_discovery_snapshot(opener=opener)
    assert len(opener.requests) == 1
    request = opener.requests[0]
    assert request.full_url == "https://hol.org/api/guard/extensions/discovery/v1/placements"
    assert request.method == "GET"
    # No credential or identifier is ever attached.
    assert not request.has_header("Authorization")
    assert not request.has_header("Cookie")
    assert cached.server_date_ms is not None


def test_fetch_reuses_fresh_results_and_conditional_etag() -> None:
    opener = FakeOpener([
        FakeResponse(snapshot_body(), headers={"ETag": '"gd1-abc"', "Date": "Mon, 13 Oct 2026 12:00:02 GMT"}),
        FakeResponse(snapshot_body(), headers={"ETag": '"gd1-abc"', "Date": "Mon, 13 Oct 2026 12:00:12 GMT"}),
    ])
    discovery.fetch_discovery_snapshot(opener=opener, force=True)
    # Within the freshness window the cached result is reused with no request.
    discovery.fetch_discovery_snapshot(opener=opener)
    assert len(opener.requests) == 1
    # A forced refetch sends the stored validator.
    discovery.fetch_discovery_snapshot(opener=opener, force=True)
    assert len(opener.requests) == 2
    assert opener.requests[1].has_header("If-none-match")


def test_http_304_reuses_the_original_body_without_restamping() -> None:
    first = FakeResponse(snapshot_body(), headers={"ETag": '"gd1-def"', "Date": "Mon, 13 Oct 2026 12:00:02 GMT"})
    opener = FakeOpener([first, http_error(304)])
    original = discovery.fetch_discovery_snapshot(opener=opener, force=True)
    opener.responses.append(http_error(304))
    reused = discovery.fetch_discovery_snapshot(opener=opener, force=True)
    assert reused.body == original.body
    assert reused.etag == original.etag
    assert reused.server_date_ms == original.server_date_ms


def test_redirects_are_refused() -> None:
    redirect = urllib.error.HTTPError(
        discovery.DISCOVERY_PLACEMENTS_PATH,
        302,
        "Found",
        hdrs=None,
        fp=io.BytesIO(b""),
    )
    opener = FakeOpener([redirect])
    with pytest.raises(discovery.DiscoveryReadError):
        discovery.fetch_discovery_snapshot(opener=opener, force=True)


def test_non_utf8_upstream_body_is_refused() -> None:
    opener = FakeOpener([FakeResponse(b"\xff")])
    with pytest.raises(discovery.DiscoveryReadError) as error:
        discovery.fetch_discovery_snapshot(opener=opener, force=True)
    assert error.value.code == discovery.DISCOVERY_TRANSPORT_FAILED


def test_non_utf8_snapshot_is_not_sent_to_the_projector(monkeypatch: pytest.MonkeyPatch) -> None:
    identity = type("Identity", (), {"path": "/usr/bin/false"})()
    capabilities = type("Capabilities", (), {
        "features": {discovery._RESIDENT_PROTOCOL_FEATURE, discovery.DISCOVERY_NATIVE_FEATURE},
    })()
    status = type("Status", (), {
        "available": True,
        "compatible": True,
        "identity": identity,
        "capabilities": capabilities,
    })()
    monkeypatch.setattr(discovery, "native_runtime_status", lambda **_kwargs: status)
    monkeypatch.setattr(
        discovery,
        "fetch_discovery_snapshot",
        lambda **_kwargs: discovery._CachedSnapshot(
            body=b"\xff",
            server_date_ms=1,
            etag=None,
            fetched_monotonic=0,
        ),
    )
    monkeypatch.setattr(discovery, "discovery_rollout_enabled", lambda: True)
    called: list[bool] = []
    monkeypatch.setattr(discovery, "native_resident_client_request", lambda **_kwargs: called.append(True))
    result = discovery.discovery_placement_projection(
        guard_home=Path("/tmp"),
        policy_allowed=True,
        opener=FakeOpener([]),
    )
    assert called == []
    assert result is not None
    assert result.status == 503
    assert result.error_code == discovery.DISCOVERY_TRANSPORT_FAILED


def test_response_bodies_beyond_64kib_are_refused() -> None:
    oversized = FakeResponse(b"x" * (discovery.MAX_DISCOVERY_RESPONSE_BYTES + 1))
    opener = FakeOpener([oversized])
    with pytest.raises(discovery.DiscoveryReadError) as error:
        discovery.fetch_discovery_snapshot(opener=opener, force=True)
    assert error.value.code == "discovery_response_too_large"


def test_rollout_switch_answers_capability_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(discovery.DISCOVERY_ROLLOUT_ENV, "off")
    assert discovery.discovery_rollout_enabled() is False
    result = discovery.discovery_placement_projection(
        guard_home=Path("/tmp"),
        policy_allowed=True,
        opener=FakeOpener([]),
    )
    assert result is not None
    assert result.status == 503
    assert result.error_code == discovery.DISCOVERY_UNAVAILABLE


def test_relay_rejects_unbounded_and_unknown_paths() -> None:
    with pytest.raises(discovery.DiscoveryReadError):
        discovery.relay_discovery_measurement(
            path="/api/guard/extensions/discovery/v1/unknown",
            payload=b"{}",
            opener=FakeOpener([]),
        )
    with pytest.raises(discovery.DiscoveryReadError):
        discovery.relay_discovery_measurement(
            path=discovery.DISCOVERY_EVENTS_PATH,
            payload=b"{" + b" " * discovery.MAX_DISCOVERY_REQUEST_BYTES + b"}",
            opener=FakeOpener([]),
        )


def test_relay_posts_only_the_bounded_body_to_the_fixed_origin() -> None:
    opener = FakeOpener([FakeResponse(b'{"accepted":1,"duplicates":0,"rejected":0}')])
    status, body = discovery.relay_discovery_measurement(
        path=discovery.DISCOVERY_EVENTS_PATH,
        payload=json.dumps({"events": [{"token": "t" * 40, "kind": "served"}]}).encode(),
        opener=opener,
    )
    assert status == 200
    assert b"accepted" in body
    request = opener.requests[0]
    assert request.full_url == "https://hol.org/api/guard/extensions/discovery/v1/events"
    assert request.method == "POST"
    assert not request.has_header("Authorization")
