"""Pure-tooling checks for the integration suite's external service boundary.

These run without importing Guard or replacing its native projector. The real
integration server must pass its authenticated discovery preflight separately.
"""

from __future__ import annotations

import http.client
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


_HEADERS = {
    "Accept": "application/json",
    "Accept-Encoding": "identity",
    "Cache-Control": "no-store",
    "User-Agent": _USER_AGENT,
}


class DiscoveryFixtureTests(unittest.TestCase):
    """The external fixture accepts only the current credential-free contract."""

    def setUp(self) -> None:
        self.server = fixture.DiscoveryFixtureServer(user_agent=_USER_AGENT)
        self.server.start()
        self.addCleanup(self.server.stop)

    def _fetch(
        self, path: str = fixture.PLACEMENTS_PATH, *, method: str = "GET", headers: dict[str, str] | None = None
    ) -> tuple[int, dict[str, str], bytes]:
        connection = http.client.HTTPConnection("127.0.0.1", int(self.server.origin.rsplit(":", 1)[1]), timeout=5)
        try:
            connection.putrequest(method, path, skip_accept_encoding=True)
            for name, value in (headers if headers is not None else _HEADERS).items():
                connection.putheader(name, value)
            connection.endheaders(b"{}" if method == "POST" else None)
            response = connection.getresponse()
            return response.status, dict(response.getheaders()), response.read()
        finally:
            connection.close()

    def test_empty_snapshot_has_current_dates_and_native_input_fields(self) -> None:
        """Generate native input shape without stubbing native acceptance."""
        now = datetime(2026, 10, 23, 12, 0, 0, 123000, tzinfo=UTC)
        with patch.object(fixture, "datetime") as clock:
            clock.now.return_value = now
            status, headers, raw = self._fetch()
        self.assertEqual(status, 200)
        body = json.loads(raw)
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
        self.assertEqual(parsedate_to_datetime(headers["Date"]), now.replace(microsecond=0))
        self.assertNotIn("ETag", headers)
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

    def test_each_fetch_has_a_fresh_lease(self) -> None:
        """Long browser suites never reuse expired fixture inventory."""
        now = datetime.now(UTC)
        with patch.object(fixture, "datetime") as clock:
            clock.now.side_effect = [now, now + timedelta(minutes=2)]
            first = json.loads(self._fetch()[2])
            second = json.loads(self._fetch()[2])
        self.assertNotEqual(first["generatedAt"], second["generatedAt"])
        self.assertEqual(self.server.request_count, 2)

    def test_unexpected_requests_are_refused(self) -> None:
        """Wrong paths, measurements and payloads fail closed."""
        for path, method in (
            (fixture.PLACEMENTS_PATH + "?token=private", "GET"),
            ("/placements", "GET"),
            (fixture.PLACEMENTS_PATH.replace("placements", "renders"), "GET"),
            (fixture.PLACEMENTS_PATH, "POST"),
        ):
            with self.subTest(path=path, method=method):
                self.assertEqual(self._fetch(path, method=method)[0], 400)
        self.assertEqual(self.server.request_count, 0)
        self.assertEqual(self.server.refusals, 4)

    def test_credentials_and_unknown_headers_are_refused(self) -> None:
        """The fixture does not silently accept leaked local identity."""
        for header, value in (
            ("Authorization", "Bearer private"),
            ("Cookie", "session=private"),
            ("X-Guard-Token", "private"),
            ("X-Device-Id", "private"),
            ("User-Agent", "other-client"),
            ("Accept", "text/plain"),
        ):
            with self.subTest(header=header):
                self.assertEqual(self._fetch(headers=_HEADERS | {header: value})[0], 400)
        self.assertEqual(self.server.request_count, 0)


class ProjectionPreflightTests(unittest.TestCase):
    """Setup fails on route/native errors rather than replacing their result."""

    def test_preflight_uses_authenticated_local_route(self) -> None:
        """Only the setup request carries the local daemon token."""
        snapshot = json.loads(fixture.placements_body(datetime.now(UTC)))
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
        raw_snapshot = fixture.placements_body(datetime.now(UTC))
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
