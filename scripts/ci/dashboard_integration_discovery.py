"""Fixture only the external discovery service; daemon and native reads stay real."""

from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from datetime import UTC, datetime, timedelta
from email.utils import format_datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PLACEMENTS_PATH = "/api/guard/extensions/discovery/v1/placements"
_MAX_RESPONSE_BYTES = 65_536
_ALLOWED_HEADERS = frozenset({"accept", "accept-encoding", "cache-control", "user-agent"})


def _timestamp(value: datetime) -> str:
    return value.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def placements_body(now: datetime) -> bytes:
    body = {
        "schemaVersion": "guard.extensions.discovery.v1",
        "snapshotId": "22222222-2222-4222-8222-222222222222",
        "state": "ready",
        "enabled": True,
        "reasonCode": None,
        "generatedAt": _timestamp(now),
        "leaseExpiresAt": _timestamp(now + timedelta(seconds=25)),
        "placements": [],
        "offers": [
            {
                "product": product,
                "availability": "unknown",
                "indicativeAmountCents": None,
                "currency": None,
                "checkedAt": None,
                "quoteRequired": True,
            }
            for product in ("always", "time_slot", "sponsored")
        ],
    }
    return json.dumps(body, separators=(",", ":")).encode("utf-8")


class DiscoveryFixtureServer:
    """Serve empty external inventory on loopback, refusing every unexpected request.

    The daemon reaches it through ``HOL_GUARD_DISCOVERY_FIXTURE_ORIGIN``, which
    it honours only for a loopback ``http`` origin.
    """

    def __init__(self, *, user_agent: str) -> None:
        self.user_agent = user_agent
        self.request_count = 0
        self.refusals = 0
        fixture = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                headers = {key.lower(): value for key, value in self.headers.items()}
                headers.pop("host", None)
                headers.pop("connection", None)
                if (
                    self.path != PLACEMENTS_PATH
                    or set(headers) - _ALLOWED_HEADERS
                    or headers.get("accept") != "application/json"
                    or headers.get("accept-encoding") != "identity"
                    or headers.get("cache-control") != "no-store"
                    or headers.get("user-agent") != fixture.user_agent
                ):
                    fixture.refusals += 1
                    self.send_error(400)
                    return
                fixture.request_count += 1
                # No ETag/304: every fetch observes a new, live 25-second lease.
                now = datetime.now(UTC)
                body = placements_body(now)
                self.send_response(200)
                self.send_header("Date", format_datetime(now, usegmt=True))
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_POST(self) -> None:
                fixture.refusals += 1
                self.send_error(400)

            def log_message(self, format: str, *args: object) -> None:  # noqa: A002
                del format, args

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    @property
    def origin(self) -> str:
        return f"http://127.0.0.1:{self._server.server_address[1]}"

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._server.shutdown()
        self._server.server_close()


def require_discovery_projection(origin: str, auth_token: str) -> None:
    """Fail setup if the authenticated daemon cannot project fixture bytes."""

    request = urllib.request.Request(
        f"{origin}/v1/discovery/extensions/placements",
        headers={"X-Guard-Token": auth_token},
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            body = response.read(_MAX_RESPONSE_BYTES + 1)
            if response.status != 200 or len(body) > _MAX_RESPONSE_BYTES:
                raise ValueError("unexpected projection response")
    except urllib.error.HTTPError as error:
        # Error codes are safe diagnostics; never print request/session headers.
        try:
            payload = json.loads(error.read(4096))
            code = payload.get("error", "unknown") if isinstance(payload, dict) else "unknown"
        except (OSError, ValueError):
            code = "unreadable"
        raise RuntimeError(f"integration discovery preflight failed: HTTP {error.code} {code}") from error
    except (urllib.error.URLError, OSError, ValueError) as error:
        raise RuntimeError("integration discovery preflight failed") from error
    try:
        projected = json.loads(body)
        if (
            not isinstance(projected, dict)
            or set(projected) != {"snapshot", "remainingLeaseMs", "policyAllowed"}
            or projected["policyAllowed"] is not True
            or type(projected["remainingLeaseMs"]) is not int
            or not 0 < projected["remainingLeaseMs"] <= 25_000
            or not isinstance(projected["snapshot"], dict)
            or projected["snapshot"].get("schemaVersion") != "guard.extensions.discovery.v1"
            or projected["snapshot"].get("placements") != []
        ):
            raise ValueError("unexpected projection body")
    except (ValueError, TypeError) as error:
        raise RuntimeError("integration discovery preflight did not return a native projection") from error
