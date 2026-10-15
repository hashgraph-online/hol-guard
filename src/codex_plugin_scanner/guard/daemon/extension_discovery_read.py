"""Authenticated adapter for sponsored extension discovery (Guard Local).

The dashboard never talks to Guard Cloud directly: ``connect-src 'self'``
stays intact and this daemon route is the only transport. The module is
strictly I/O: one bounded worker, a fixed HTTPS origin and path, no
redirects, no cookies, no caller-selected URLs, and no local credential ever
placed on the wire. Every upstream byte is validated and projected by the
native ``discovery_placement_project`` operation; this module never parses,
selects, ranks, or re-serializes placements. When the native capability is
absent the route answers unavailability — there is no Python fallback.

Rollback: ``HOL_GUARD_DISCOVERY=off`` makes every route answer
``capability_unavailable`` without dispatching upstream or native work.
"""

from __future__ import annotations

import json
import os
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Protocol, cast

from ...no_redirect import RejectRedirects
from ..mdm.network_transport import managed_opener
from ..native_resident_client import native_resident_client_request
from ..native_runtime import NativeRuntimeStatus, _isolated_environment, native_runtime_status
from ..strict_json_pairs import unique_json_object

DISCOVERY_ROLLOUT_ENV = "HOL_GUARD_DISCOVERY"
DISCOVERY_UNAVAILABLE = "discovery_capability_unavailable"
DISCOVERY_TRANSPORT_FAILED = "discovery_transport_failed"

# Fixed upstream: production callers can select neither host nor path.
DISCOVERY_CLOUD_ORIGIN = "https://hol.org"
DISCOVERY_PLACEMENTS_PATH = "/api/guard/extensions/discovery/v1/placements"
DISCOVERY_RENDERS_PATH = "/api/guard/extensions/discovery/v1/renders"
DISCOVERY_EVENTS_PATH = "/api/guard/extensions/discovery/v1/events"

MAX_DISCOVERY_RESPONSE_BYTES = 65_536
MAX_DISCOVERY_REQUEST_BYTES = 16_384
DISCOVERY_IO_DEADLINE_SECONDS = 2.0
# Coalescing window: concurrent dashboard tabs share one upstream result and
# one native projection per poll cadence instead of multiplying requests.
DISCOVERY_FRESH_RESULT_SECONDS = 10.0

DISCOVERY_NATIVE_FEATURE = "discovery-placement-projection-v1"
_RESIDENT_PROTOCOL_FEATURE = "resident-protocol-v2"
DISCOVERY_REQUEST_SCHEMA = "guard-discovery-project-request.v1"
DISCOVERY_RESULT_SCHEMA = "guard-discovery-project-result.v1"
_RESULT_FIELDS = frozenset({"schema", "outcome", "http_status", "etag", "body", "error_code"})
_ERROR_STATUS = {
    "discovery_request_invalid": 400,
    "discovery_body_invalid": 400,
    "discovery_snapshot_invalid": 503,
}

_DISABLED_VALUES = frozenset({"0", "off", "false", "disabled"})


def discovery_rollout_enabled(environ: dict[str, str] | None = None) -> bool:
    source = environ if environ is not None else os.environ
    return source.get(DISCOVERY_ROLLOUT_ENV, "").strip().lower() not in _DISABLED_VALUES


class DiscoveryReadError(Exception):
    def __init__(self, code: str, status: int) -> None:
        super().__init__(code)
        self.code = code
        self.status = status


@dataclass(frozen=True, slots=True)
class DiscoveryProjection:
    """Native projection or a typed transport failure. This is not a catalog read."""

    status: int
    etag: str | None = None
    body: bytes | None = None
    error_code: str | None = None


@dataclass(frozen=True, slots=True)
class _CachedSnapshot:
    body: bytes
    server_date_ms: int | None
    etag: str | None
    fetched_monotonic: float


_fetch_lock = threading.Lock()
_cached_snapshot: _CachedSnapshot | None = None


class _DiscoveryHeaders(Protocol):
    def get(self, name: str, /) -> str | None: ...


class _ReadableBody(Protocol):
    def read(self, amount: int, /) -> bytes: ...


class _DiscoveryResponse(_ReadableBody, Protocol):
    @property
    def status(self) -> int: ...

    @property
    def headers(self) -> _DiscoveryHeaders: ...

    def close(self) -> None: ...


class DiscoveryOpener(Protocol):
    def open(self, request: urllib.request.Request, timeout: float) -> _DiscoveryResponse: ...


def _build_opener() -> DiscoveryOpener:
    # urllib.request.build_opener stays inside the enterprise transport.
    # Redirects stay refused. This route still cannot select a host, path,
    # cookie, or credential.
    opened: object = managed_opener(redirect_handler=RejectRedirects())
    return cast(DiscoveryOpener, opened)


def _parse_http_date_ms(value: str | None) -> int | None:
    if not value:
        return None
    try:
        return int(parsedate_to_datetime(value).timestamp() * 1000)
    except (TypeError, ValueError, OverflowError):
        return None


def _read_bounded(response: _ReadableBody, limit: int) -> bytes:
    # Bound the read while streaming rather than after allocating a body.
    chunks: list[bytes] = []
    size = 0
    while size < limit:
        chunk = response.read(min(8192, limit - size))
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)
        size += len(chunk)
    # One extra byte proves the body exceeded the bound.
    if response.read(1):
        raise DiscoveryReadError("discovery_response_too_large", 503)
    return b"".join(chunks)


def _supports_discovery(status: NativeRuntimeStatus) -> bool:
    if not status.available or not status.compatible or status.identity is None or status.capabilities is None:
        return False
    features = set(status.capabilities.features)
    return _RESIDENT_PROTOCOL_FEATURE in features and DISCOVERY_NATIVE_FEATURE in features


def fetch_discovery_snapshot(
    *,
    opener: DiscoveryOpener | None = None,
    timeout_seconds: float = DISCOVERY_IO_DEADLINE_SECONDS,
    force: bool = False,
) -> _CachedSnapshot:
    """Fetch (or coalesce) the fixed-origin snapshot inside one worker.

    The lock is the single bounded worker: at most one upstream request is in
    flight per daemon and concurrent callers reuse its fresh result. A 304
    reuses the original body, server date, and times — it never restamps the
    eligibility observation.
    """

    global _cached_snapshot
    with _fetch_lock:
        now = time.monotonic()
        if (
            not force
            and _cached_snapshot is not None
            and now - _cached_snapshot.fetched_monotonic < DISCOVERY_FRESH_RESULT_SECONDS
        ):
            return _cached_snapshot
        request = urllib.request.Request(
            DISCOVERY_CLOUD_ORIGIN + DISCOVERY_PLACEMENTS_PATH,
            method="GET",
            headers={
                "Accept": "application/json",
                # Identity encoding keeps the byte bound equal to the
                # decompressed bound; no transparent compression surprises.
                "Accept-Encoding": "identity",
                "Cache-Control": "no-store",
                **({"If-None-Match": _cached_snapshot.etag} if _cached_snapshot and _cached_snapshot.etag else {}),
            },
        )
        # No Authorization, Cookie, or local identifier is ever attached.
        handler = opener if opener is not None else _build_opener()
        try:
            response = handler.open(request, timeout=timeout_seconds)
        except urllib.error.HTTPError as error:
            if error.code == 304 and _cached_snapshot is not None:
                reused = _CachedSnapshot(
                    body=_cached_snapshot.body,
                    server_date_ms=_cached_snapshot.server_date_ms,
                    etag=_cached_snapshot.etag,
                    fetched_monotonic=now,
                )
                _cached_snapshot = reused
                return reused
            raise DiscoveryReadError("discovery_upstream_error", 503) from error
        except (urllib.error.URLError, OSError, ValueError) as error:
            raise DiscoveryReadError(DISCOVERY_TRANSPORT_FAILED, 503) from error
        try:
            if response.status != 200:
                raise DiscoveryReadError("discovery_upstream_error", 503)
            body = _read_bounded(response, MAX_DISCOVERY_RESPONSE_BYTES)
            try:
                body.decode("utf-8")
            except UnicodeDecodeError as error:
                raise DiscoveryReadError(DISCOVERY_TRANSPORT_FAILED, 503) from error
            etag = response.headers.get("ETag")
            server_date_ms = _parse_http_date_ms(response.headers.get("Date"))
        finally:
            close = getattr(response, "close", None)
            if close is not None:
                close()
        cached = _CachedSnapshot(
            body=body,
            server_date_ms=server_date_ms,
            etag=etag,
            fetched_monotonic=now,
        )
        _cached_snapshot = cached
        return cached


def _validated_result(decoded: object) -> DiscoveryProjection | None:
    if not isinstance(decoded, dict) or set(decoded) != _RESULT_FIELDS or decoded["schema"] != DISCOVERY_RESULT_SCHEMA:
        return None
    outcome, status = decoded["outcome"], decoded["http_status"]
    body, error_code = decoded["body"], decoded["error_code"]
    if outcome == "ok":
        if status != 200 or error_code is not None or not isinstance(body, str):
            return None
        encoded = body.encode("utf-8")
        if len(encoded) > MAX_DISCOVERY_RESPONSE_BYTES:
            return None
        return DiscoveryProjection(status=200, etag=None, body=encoded)
    if outcome == "error":
        if not isinstance(error_code, str) or _ERROR_STATUS.get(error_code) != status:
            return None
        if body is not None:
            return None
        return DiscoveryProjection(status=status, error_code=error_code)
    return None


def discovery_placement_projection(
    *,
    guard_home: Path,
    policy_allowed: bool,
    opener: DiscoveryOpener | None = None,
    timeout_seconds: float = 2.0,
) -> DiscoveryProjection | None:
    """Return the native-validated projection, or ``None`` for capability absence.

    ``None`` means no native runtime/capability/frame agreement: the caller
    answers unavailability and no paid fallback exists. Transport failures
    answer a typed 503 error result instead.
    """

    if not discovery_rollout_enabled():
        return DiscoveryProjection(status=503, error_code=DISCOVERY_UNAVAILABLE)
    deadline = time.monotonic() + timeout_seconds
    status = native_runtime_status(deadline_monotonic=deadline)
    if not _supports_discovery(status) or status.identity is None:
        return None
    try:
        snapshot = fetch_discovery_snapshot(
            opener=opener,
            timeout_seconds=max(0.05, min(timeout_seconds, deadline - time.monotonic())),
        )
    except DiscoveryReadError as error:
        return DiscoveryProjection(status=error.status, error_code=error.code)
    try:
        body_text = snapshot.body.decode("utf-8")
    except UnicodeDecodeError:
        return DiscoveryProjection(status=503, error_code=DISCOVERY_TRANSPORT_FAILED)
    envelope = {
        "operation": "discovery_placement_project",
        "request": {
            "schema": DISCOVERY_REQUEST_SCHEMA,
            "body": body_text,
            "server_date_ms": snapshot.server_date_ms,
            "now_wall_ms": int(time.time() * 1000),
            "policy_allowed": bool(policy_allowed),
        },
        "deadline_budget_ms": max(1, int((deadline - time.monotonic()) * 1000)),
    }
    payload = json.dumps(envelope, separators=(",", ":")).encode("utf-8")
    response = native_resident_client_request(
        executable=status.identity.path,
        guard_home=guard_home,
        environment=_isolated_environment(),
        payload=payload,
        timeout_seconds=max(0.001, deadline - time.monotonic()),
        deadline_monotonic=deadline,
    )
    # Discovery stays out of the shared resident health that gates hook
    # execution: an advertising fault must never open the protection circuit.
    if response is None:
        return DiscoveryProjection(status=503, error_code=DISCOVERY_TRANSPORT_FAILED)
    try:
        decoded = json.loads(response.decode("utf-8"), object_pairs_hook=unique_json_object)
    except (UnicodeDecodeError, ValueError):
        return None
    return _validated_result(decoded)


def relay_discovery_measurement(
    *,
    path: str,
    payload: bytes,
    opener: DiscoveryOpener | None = None,
    timeout_seconds: float = DISCOVERY_IO_DEADLINE_SECONDS,
) -> tuple[int, bytes]:
    """Relay a consented render/event request to the fixed origin.

    Only the bounded JSON body moves; no local credential, identifier, or
    inventory is attached. Relay failure is a typed error for the dashboard
    and never blocks a card or navigation.
    """

    if path not in (DISCOVERY_RENDERS_PATH, DISCOVERY_EVENTS_PATH):
        raise DiscoveryReadError("discovery_request_invalid", 400)
    if len(payload) > MAX_DISCOVERY_REQUEST_BYTES:
        raise DiscoveryReadError("discovery_request_invalid", 400)
    request = urllib.request.Request(
        DISCOVERY_CLOUD_ORIGIN + path,
        data=payload,
        method="POST",
        headers={
            "Accept": "application/json",
            "Accept-Encoding": "identity",
            "Content-Type": "application/json",
            "Cache-Control": "no-store",
        },
    )
    handler = opener if opener is not None else _build_opener()
    try:
        response = handler.open(request, timeout=timeout_seconds)
    except urllib.error.HTTPError as error:
        try:
            body = _read_bounded(error, 4096)
        except (DiscoveryReadError, OSError):
            body = b'{"error":"relay_failed"}'
        return error.code, body
    except (urllib.error.URLError, OSError, ValueError) as error:
        raise DiscoveryReadError(DISCOVERY_TRANSPORT_FAILED, 503) from error
    try:
        if response.status != 200:
            raise DiscoveryReadError("discovery_upstream_error", 503)
        return 200, _read_bounded(response, MAX_DISCOVERY_RESPONSE_BYTES)
    finally:
        close = getattr(response, "close", None)
        if close is not None:
            close()


def reset_discovery_cache_for_tests() -> None:
    global _cached_snapshot
    with _fetch_lock:
        _cached_snapshot = None


__all__ = [
    "DISCOVERY_CLOUD_ORIGIN",
    "DISCOVERY_EVENTS_PATH",
    "DISCOVERY_IO_DEADLINE_SECONDS",
    "DISCOVERY_PLACEMENTS_PATH",
    "DISCOVERY_RENDERS_PATH",
    "DISCOVERY_REQUEST_SCHEMA",
    "DISCOVERY_RESULT_SCHEMA",
    "DISCOVERY_ROLLOUT_ENV",
    "DISCOVERY_TRANSPORT_FAILED",
    "DISCOVERY_UNAVAILABLE",
    "MAX_DISCOVERY_REQUEST_BYTES",
    "MAX_DISCOVERY_RESPONSE_BYTES",
    "DiscoveryReadError",
    "discovery_placement_projection",
    "discovery_rollout_enabled",
    "fetch_discovery_snapshot",
    "relay_discovery_measurement",
    "reset_discovery_cache_for_tests",
]
