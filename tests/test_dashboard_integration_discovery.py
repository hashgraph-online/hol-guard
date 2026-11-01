"""Pure-tooling checks for the integration suite's external service boundary.

These run without importing Guard or replacing its native projector. The real
integration server must pass its authenticated discovery preflight separately.
"""

from __future__ import annotations

import io
import json
import unittest
import urllib.error
import urllib.request
from datetime import UTC, datetime, timedelta
from email.utils import parsedate_to_datetime
from unittest.mock import patch

from scripts.ci import dashboard_integration_discovery as fixture

_USER_AGENT = "hol-guard/fixture"


class _RouteResponse(io.BytesIO):
    status = 200


def _request(url: str = fixture.PLACEMENTS_URL, **kwargs: object) -> urllib.request.Request:
    return urllib.request.Request(
        url,
        headers={
            "Accept": "application/json",
            "Accept-Encoding": "identity",
            "Cache-Control": "no-store",
            "User-Agent": _USER_AGENT,
        },
        **kwargs,
    )


class DiscoveryFixtureTests(unittest.TestCase):
    """The external fixture accepts only the current credential-free contract."""

    def test_empty_snapshot_has_current_dates_and_native_input_fields(self) -> None:
        """Generate native input shape without stubbing native acceptance."""
        now = datetime(2026, 10, 23, 12, 0, 0, 123000, tzinfo=UTC)
        with patch.object(fixture, "datetime") as clock:
            clock.now.return_value = now
            response = fixture.DiscoveryFixtureOpener(user_agent=_USER_AGENT).open(_request(), timeout=2)
        body = json.loads(response.read())
        self.assertEqual(
            set(body),
            {
                "schemaVersion",
                "snapshotId",
                "state",
                "enabled",
                "reasonCode",
                "generatedAt",
                "leaseExpiresAt",
                "placements",
                "offers",
            },
        )
        self.assertEqual(body["schemaVersion"], "guard.extensions.discovery.v1")
        self.assertEqual(body["state"], "ready")
        self.assertIs(body["enabled"], True)
        self.assertIsNone(body["reasonCode"])
        self.assertEqual(body["placements"], [])
        self.assertEqual(datetime.fromisoformat(body["generatedAt"]), now)
        self.assertEqual(datetime.fromisoformat(body["leaseExpiresAt"]), now + timedelta(seconds=25))
        self.assertEqual(parsedate_to_datetime(response.headers["Date"]), now.replace(microsecond=0))
        self.assertNotIn("ETag", response.headers)
        self.assertEqual([offer["product"] for offer in body["offers"]], ["always", "time_slot", "sponsored"])
        for offer in body["offers"]:
            self.assertEqual(
                offer | {"product": "any"},
                {
                    "product": "any",
                    "availability": "unknown",
                    "indicativeAmountCents": None,
                    "currency": None,
                    "checkedAt": None,
                    "quoteRequired": True,
                },
            )

    def test_each_fetch_has_a_fresh_independent_stream_and_lease(self) -> None:
        """Long browser suites never reuse expired fixture inventory."""
        now = datetime.now(UTC)
        opener = fixture.DiscoveryFixtureOpener(user_agent=_USER_AGENT)
        with patch.object(fixture, "datetime") as clock:
            clock.now.side_effect = [now, now + timedelta(minutes=2)]
            first = opener.open(_request(), timeout=1)
            second = opener.open(_request(), timeout=1)
        self.assertNotEqual(json.loads(first.read())["generatedAt"], json.loads(second.read())["generatedAt"])
        self.assertEqual(opener.request_count, 2)
        first.close()
        self.assertFalse(second.closed)

    def test_unexpected_requests_never_fall_back_to_network(self) -> None:
        """Wrong destinations, measurements, payloads and budgets fail closed."""
        requests = [
            _request("http://hol.org/api/guard/extensions/discovery/v1/placements"),
            _request(fixture.PLACEMENTS_URL + "?token=private"),
            _request("https://example.invalid/placements"),
            _request(fixture.PLACEMENTS_URL.replace("placements", "renders")),
            _request(method="POST"),
            _request(data=b"{}", method="GET"),
        ]
        opener = fixture.DiscoveryFixtureOpener(user_agent=_USER_AGENT)
        with patch.object(urllib.request, "urlopen", side_effect=AssertionError("network called")):
            for request in requests:
                with self.subTest(url=request.full_url, method=request.get_method()), self.assertRaises(ValueError):
                    opener.open(request, timeout=1)
            for timeout in (0, -1, 3, float("inf"), float("nan")):
                with self.subTest(timeout=timeout), self.assertRaises(ValueError):
                    opener.open(_request(), timeout=timeout)
        self.assertEqual(opener.request_count, 0)

    def test_credentials_unknown_headers_and_large_values_are_rejected(self) -> None:
        """The fixture does not silently accept leaked local identity."""
        opener = fixture.DiscoveryFixtureOpener(user_agent=_USER_AGENT)
        for header, value in (
            ("Authorization", "Bearer private"),
            ("Cookie", "session=private"),
            ("X-Guard-Token", "private"),
            ("X-Device-Id", "private"),
            ("User-Agent", "other-client"),
            ("User-Agent", "x" * 257),
            ("Accept", "text/plain"),
            ("Accept", "application/json\r\nprivate"),
        ):
            request = _request()
            request.add_header(header, value)
            with self.subTest(header=header), self.assertRaises(ValueError):
                opener.open(request, timeout=1)
        self.assertEqual(opener.request_count, 0)


class ProjectionPreflightTests(unittest.TestCase):
    """Setup fails on route/native errors rather than replacing their result."""

    def test_preflight_uses_authenticated_local_route(self) -> None:
        """Only the setup request carries the local daemon token."""
        snapshot = json.loads(fixture.DiscoveryFixtureResponse(datetime.now(UTC)).read())
        response = _RouteResponse(
            json.dumps({"snapshot": snapshot, "remainingLeaseMs": 24000, "policyAllowed": True}).encode()
        )
        with patch.object(urllib.request, "urlopen", return_value=response) as opened:
            fixture.require_discovery_projection("http://127.0.0.1:4791", "fixture-daemon-token")
        request = opened.call_args.args[0]
        self.assertEqual(request.full_url, "http://127.0.0.1:4791/v1/discovery/extensions/placements")
        self.assertEqual(request.get_header("X-guard-token"), "fixture-daemon-token")

    def test_typed_resident_or_transport_failure_stops_setup(self) -> None:
        """A 503 remains an error, including its bounded diagnostic code."""
        error = urllib.error.HTTPError(
            "http://127.0.0.1:4791/v1/discovery/extensions/placements",
            503,
            "failed",
            None,
            io.BytesIO(b'{"error":"discovery_transport_failed"}'),
        )
        with (
            patch.object(urllib.request, "urlopen", side_effect=error),
            self.assertRaisesRegex(
                RuntimeError,
                "HTTP 503 discovery_transport_failed",
            ),
        ):
            fixture.require_discovery_projection("http://127.0.0.1:4791", "fixture-token")

    def test_raw_or_oversized_body_cannot_masquerade_as_native_projection(self) -> None:
        """A successful HTTP status alone does not satisfy the preflight."""
        raw_snapshot = fixture.DiscoveryFixtureResponse(datetime.now(UTC)).read()
        for body in (b"{}", b"not-json", raw_snapshot, b"x" * 65537):
            response = _RouteResponse(body)
            with (
                self.subTest(size=len(body)),
                patch.object(urllib.request, "urlopen", return_value=response),
                self.assertRaises(RuntimeError),
            ):
                fixture.require_discovery_projection("http://127.0.0.1:4791", "fixture-token")


if __name__ == "__main__":
    unittest.main()
