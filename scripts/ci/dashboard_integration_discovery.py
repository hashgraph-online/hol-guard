"""Fixture only the external discovery service; daemon and native reads stay real."""

from __future__ import annotations

import io
import json
import math
import urllib.error
import urllib.request
from datetime import UTC, datetime, timedelta
from email.utils import format_datetime

PLACEMENTS_URL = "https://hol.org/api/guard/extensions/discovery/v1/placements"
_MAX_RESPONSE_BYTES = 65_536
_ALLOWED_HEADERS = frozenset({"accept", "accept-encoding", "cache-control", "user-agent"})


def _timestamp(value: datetime) -> str:
    return value.isoformat(timespec="milliseconds").replace("+00:00", "Z")


class DiscoveryFixtureResponse(io.BytesIO):
    """A fresh upstream byte stream consumed by the real bounded reader."""

    status = 200

    def __init__(self, now: datetime) -> None:
        self.headers = {"Date": format_datetime(now, usegmt=True), "Content-Type": "application/json"}
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
        super().__init__(json.dumps(body, separators=(",", ":")).encode("utf-8"))


class DiscoveryFixtureOpener:
    """Serve empty external inventory, refusing every unexpected wire request."""

    def __init__(self, *, user_agent: str) -> None:
        self.user_agent = user_agent
        self.request_count = 0

    def open(self, request: urllib.request.Request, timeout: float) -> DiscoveryFixtureResponse:
        if request.full_url != PLACEMENTS_URL or request.get_method() != "GET" or request.data is not None:
            raise ValueError("unexpected integration discovery request")
        headers = {key.lower(): value for key, value in request.header_items()}
        if (
            set(headers) - _ALLOWED_HEADERS
            or headers.get("accept") != "application/json"
            or headers.get("accept-encoding") != "identity"
            or headers.get("cache-control") != "no-store"
            or headers.get("user-agent") != self.user_agent
            or any(len(value) > 256 or "\r" in value or "\n" in value for value in headers.values())
        ):
            raise ValueError("unexpected integration discovery headers")
        if not math.isfinite(timeout) or not 0 < timeout <= 2:
            raise ValueError("unexpected integration discovery timeout")
        self.request_count += 1
        # No ETag/304: every fetch observes a new, live 25-second lease.
        return DiscoveryFixtureResponse(datetime.now(UTC))


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
