"""Adapter for the published release archive (Guard Local).

The dashboard never talks to the portal directly: ``connect-src 'self'``
stays intact and this daemon route is the only transport. The module is
strictly I/O: one bounded worker, a fixed HTTPS origin and path set, no
redirects, no cookies, no caller-selected URLs, and no local credential,
account, or device identifier ever placed on the wire. Every upstream byte is
validated and projected by the native ``release_feed_project`` operation; this
module never parses, filters, or re-serializes a release. When the native
capability is absent the route answers unavailability — there is no Python
fallback.

Rollback: ``HOL_GUARD_RELEASE_FEED=off`` makes every route answer
``capability_unavailable`` without dispatching upstream or native work.
"""

from __future__ import annotations

import http.client
import json
import os
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, cast

from ...no_redirect import RejectRedirects
from ...version import __version__
from ..mdm.network_transport import managed_opener
from ..native_resident_client import native_resident_client_request
from ..native_runtime import NativeRuntimeStatus, _isolated_environment, native_runtime_status
from ..strict_json_pairs import unique_json_object

RELEASE_FEED_ROLLOUT_ENV = "HOL_GUARD_RELEASE_FEED"
RELEASE_FEED_UNAVAILABLE = "release_feed_capability_unavailable"
RELEASE_FEED_TRANSPORT_FAILED = "release_feed_transport_failed"
RELEASE_FEED_REQUEST_INVALID = "release_feed_request_invalid"

# Fixed upstream: callers can select neither host nor path.
RELEASE_FEED_ORIGIN = "https://hol.org"
RELEASE_INDEX_PATH = "/api/guard/releases/v1/index"
RELEASE_DETAIL_PATH = "/api/guard/releases/v1/release"

# Edges in front of the origin reject the interpreter's default agent string.
# The value carries the product and its version and no device, account, or
# installation identifier.
RELEASE_FEED_USER_AGENT = f"hol-guard/{__version__}"

MAX_RELEASE_FEED_RESPONSE_BYTES = 262_144
RELEASE_FEED_IO_DEADLINE_SECONDS = 4.0
# Release history changes a few times a week; one fetch serves every tab that
# opens the screen inside the window.
RELEASE_FEED_FRESH_RESULT_SECONDS = 300.0
# Bound the cache so a sequence of detail reads cannot grow it without end.
MAX_CACHED_RELEASE_DOCUMENTS = 32

RELEASE_FEED_NATIVE_FEATURE = "release-feed-projection-v1"
_RESIDENT_PROTOCOL_FEATURE = "resident-protocol-v2"
RELEASE_FEED_REQUEST_SCHEMA = "guard-release-feed-project-request.v1"
RELEASE_FEED_RESULT_SCHEMA = "guard-release-feed-project-result.v1"
_RESULT_FIELDS = frozenset({"schema", "outcome", "http_status", "etag", "body", "error_code"})
_ERROR_STATUS = {
    "release_feed_request_invalid": 400,
    "release_feed_body_invalid": 400,
    "release_feed_payload_invalid": 502,
}

# A slug is a minted registry key, never a path; this mirrors the portal's own
# acceptance so an unusable slug costs no upstream request.
_SLUG_PATTERN = re.compile(r"^[a-z0-9][a-z0-9.-]{0,127}$")
MAX_RELEASE_FEED_PAGE = 1_000
MAX_RELEASE_FEED_PAGE_SIZE = 50

_DISABLED_VALUES = frozenset({"0", "off", "false", "disabled"})


def release_feed_rollout_enabled(environ: dict[str, str] | None = None) -> bool:
    source = environ if environ is not None else os.environ
    return source.get(RELEASE_FEED_ROLLOUT_ENV, "").strip().lower() not in _DISABLED_VALUES


class ReleaseFeedReadError(Exception):
    def __init__(self, code: str, status: int) -> None:
        super().__init__(code)
        self.code = code
        self.status = status


@dataclass(frozen=True, slots=True)
class ReleaseFeedProjection:
    """Native projection or a typed transport failure."""

    status: int
    etag: str | None = None
    body: bytes | None = None
    error_code: str | None = None


@dataclass(frozen=True, slots=True)
class _CachedDocument:
    body: bytes
    etag: str | None
    fetched_monotonic: float


_fetch_lock = threading.Lock()
_cached_documents: dict[str, _CachedDocument] = {}


class _FeedHeaders(Protocol):
    def get(self, name: str, /) -> str | None: ...


class _ReadableBody(Protocol):
    def read(self, amount: int, /) -> bytes: ...


class _FeedResponse(_ReadableBody, Protocol):
    @property
    def status(self) -> int: ...

    @property
    def headers(self) -> _FeedHeaders: ...

    def close(self) -> None: ...


class ReleaseFeedOpener(Protocol):
    def open(self, request: urllib.request.Request, timeout: float) -> _FeedResponse: ...


def _build_opener() -> ReleaseFeedOpener:
    # urllib.request.build_opener stays inside the enterprise transport.
    # Redirects stay refused. This route still cannot select a host, path,
    # cookie, or credential.
    opened: object = managed_opener(redirect_handler=RejectRedirects())
    return cast(ReleaseFeedOpener, opened)


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
        raise ReleaseFeedReadError("release_feed_response_too_large", 502)
    return b"".join(chunks)


def _supports_release_feed(status: NativeRuntimeStatus) -> bool:
    if not status.available or not status.compatible or status.identity is None or status.capabilities is None:
        return False
    features = set(status.capabilities.features)
    return _RESIDENT_PROTOCOL_FEATURE in features and RELEASE_FEED_NATIVE_FEATURE in features


def release_feed_target(
    *,
    kind: str,
    slug: str | None = None,
    page: int = 1,
    page_size: int = MAX_RELEASE_FEED_PAGE_SIZE,
) -> tuple[str, str]:
    """Return the ``(path, query)`` for a bounded read, or raise a typed error.

    The caller supplies a paging position or a slug and nothing else: the
    host, path, and parameter names are fixed here.
    """

    if kind == "index":
        if not (1 <= page <= MAX_RELEASE_FEED_PAGE):
            raise ReleaseFeedReadError(RELEASE_FEED_REQUEST_INVALID, 400)
        if not (1 <= page_size <= MAX_RELEASE_FEED_PAGE_SIZE):
            raise ReleaseFeedReadError(RELEASE_FEED_REQUEST_INVALID, 400)
        query = urllib.parse.urlencode({"page": page, "pageSize": page_size})
        return RELEASE_INDEX_PATH, query
    if kind == "detail":
        if slug is None or not _SLUG_PATTERN.match(slug):
            raise ReleaseFeedReadError(RELEASE_FEED_REQUEST_INVALID, 400)
        return RELEASE_DETAIL_PATH, urllib.parse.urlencode({"slug": slug})
    raise ReleaseFeedReadError(RELEASE_FEED_REQUEST_INVALID, 400)


def fetch_release_document(
    *,
    path: str,
    query: str,
    opener: ReleaseFeedOpener | None = None,
    timeout_seconds: float = RELEASE_FEED_IO_DEADLINE_SECONDS,
    force: bool = False,
) -> _CachedDocument:
    """Fetch (or coalesce) one fixed-origin document inside one worker.

    The lock is the single bounded worker: at most one upstream request is in
    flight per daemon and concurrent callers reuse its fresh result. A 304
    reuses the cached body rather than restamping it.
    """

    cache_key = f"{path}?{query}"
    with _fetch_lock:
        now = time.monotonic()
        cached = _cached_documents.get(cache_key)
        if not force and cached is not None and now - cached.fetched_monotonic < RELEASE_FEED_FRESH_RESULT_SECONDS:
            return cached
        request = urllib.request.Request(
            f"{RELEASE_FEED_ORIGIN}{path}?{query}",
            method="GET",
            headers={
                "Accept": "application/json",
                # Identity encoding keeps the byte bound equal to the
                # decompressed bound; no transparent compression surprises.
                "Accept-Encoding": "identity",
                "User-Agent": RELEASE_FEED_USER_AGENT,
                **({"If-None-Match": cached.etag} if cached and cached.etag else {}),
            },
        )
        # No Authorization, Cookie, or local identifier is ever attached.
        handler = opener if opener is not None else _build_opener()
        try:
            response = handler.open(request, timeout=timeout_seconds)
        except urllib.error.HTTPError as error:
            if error.code == 304 and cached is not None:
                reused = _CachedDocument(body=cached.body, etag=cached.etag, fetched_monotonic=now)
                _cached_documents[cache_key] = reused
                return reused
            if error.code == 404:
                raise ReleaseFeedReadError("release_not_found", 404) from error
            raise ReleaseFeedReadError("release_feed_upstream_error", 502) from error
        except (urllib.error.URLError, http.client.HTTPException, OSError, ValueError) as error:
            raise ReleaseFeedReadError(RELEASE_FEED_TRANSPORT_FAILED, 503) from error
        try:
            if response.status != 200:
                raise ReleaseFeedReadError("release_feed_upstream_error", 502)
            body = _read_bounded(response, MAX_RELEASE_FEED_RESPONSE_BYTES)
            try:
                body.decode("utf-8")
            except UnicodeDecodeError as error:
                raise ReleaseFeedReadError(RELEASE_FEED_TRANSPORT_FAILED, 503) from error
            etag = response.headers.get("ETag")
        except ReleaseFeedReadError:
            raise
        except (urllib.error.URLError, http.client.HTTPException, OSError, ValueError) as error:
            # A connection that dies while its body is read is the same
            # transport failure as one that never opened, and the route owes
            # the dashboard that answer rather than a traceback.
            raise ReleaseFeedReadError(RELEASE_FEED_TRANSPORT_FAILED, 503) from error
        finally:
            close = getattr(response, "close", None)
            if close is not None:
                close()
        document = _CachedDocument(body=body, etag=etag, fetched_monotonic=now)
        if len(_cached_documents) >= MAX_CACHED_RELEASE_DOCUMENTS and cache_key not in _cached_documents:
            # Oldest insertion first: the archive index stays warm because the
            # dashboard reads it on every visit.
            _cached_documents.pop(next(iter(_cached_documents)), None)
        _cached_documents[cache_key] = document
        return document


def _validated_result(decoded: object) -> ReleaseFeedProjection | None:
    if (
        not isinstance(decoded, dict)
        or set(decoded) != _RESULT_FIELDS
        or decoded["schema"] != RELEASE_FEED_RESULT_SCHEMA
    ):
        return None
    outcome, status = decoded["outcome"], decoded["http_status"]
    body, error_code = decoded["body"], decoded["error_code"]
    if outcome == "ok":
        if status != 200 or error_code is not None or not isinstance(body, str):
            return None
        encoded = body.encode("utf-8")
        if len(encoded) > MAX_RELEASE_FEED_RESPONSE_BYTES:
            return None
        return ReleaseFeedProjection(status=200, etag=None, body=encoded)
    if outcome == "error":
        if not isinstance(error_code, str) or _ERROR_STATUS.get(error_code) != status:
            return None
        if body is not None:
            return None
        return ReleaseFeedProjection(status=status, error_code=error_code)
    return None


def release_feed_projection(
    *,
    guard_home: Path,
    kind: str,
    slug: str | None = None,
    page: int = 1,
    page_size: int = MAX_RELEASE_FEED_PAGE_SIZE,
    opener: ReleaseFeedOpener | None = None,
    timeout_seconds: float = RELEASE_FEED_IO_DEADLINE_SECONDS,
) -> ReleaseFeedProjection | None:
    """Return the native-validated projection, or ``None`` for capability absence.

    ``None`` means no native runtime/capability/frame agreement: the caller
    answers unavailability and no Python fallback exists. Transport failures
    answer a typed error result instead.
    """

    if not release_feed_rollout_enabled():
        return ReleaseFeedProjection(status=503, error_code=RELEASE_FEED_UNAVAILABLE)
    try:
        path, query = release_feed_target(kind=kind, slug=slug, page=page, page_size=page_size)
    except ReleaseFeedReadError as error:
        return ReleaseFeedProjection(status=error.status, error_code=error.code)
    deadline = time.monotonic() + timeout_seconds
    status = native_runtime_status(deadline_monotonic=deadline)
    if not _supports_release_feed(status) or status.identity is None:
        return None
    try:
        document = fetch_release_document(
            path=path,
            query=query,
            opener=opener,
            timeout_seconds=max(0.05, min(timeout_seconds, deadline - time.monotonic())),
        )
    except ReleaseFeedReadError as error:
        return ReleaseFeedProjection(status=error.status, error_code=error.code)
    try:
        body_text = document.body.decode("utf-8")
    except UnicodeDecodeError:
        return ReleaseFeedProjection(status=503, error_code=RELEASE_FEED_TRANSPORT_FAILED)
    envelope = {
        "operation": "release_feed_project",
        "request": {
            "schema": RELEASE_FEED_REQUEST_SCHEMA,
            "kind": kind,
            "body": body_text,
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
    # The release screen stays out of the shared resident health that gates
    # hook execution: a reading fault must never open the protection circuit.
    if response is None:
        return ReleaseFeedProjection(status=503, error_code=RELEASE_FEED_TRANSPORT_FAILED)
    try:
        decoded = json.loads(response.decode("utf-8"), object_pairs_hook=unique_json_object)
    except (UnicodeDecodeError, ValueError):
        return None
    return _validated_result(decoded)


def reset_release_feed_cache_for_tests() -> None:
    global _cached_documents
    with _fetch_lock:
        _cached_documents = {}


__all__ = [
    "MAX_RELEASE_FEED_PAGE",
    "MAX_RELEASE_FEED_PAGE_SIZE",
    "MAX_RELEASE_FEED_RESPONSE_BYTES",
    "RELEASE_DETAIL_PATH",
    "RELEASE_FEED_IO_DEADLINE_SECONDS",
    "RELEASE_FEED_ORIGIN",
    "RELEASE_FEED_REQUEST_INVALID",
    "RELEASE_FEED_REQUEST_SCHEMA",
    "RELEASE_FEED_RESULT_SCHEMA",
    "RELEASE_FEED_ROLLOUT_ENV",
    "RELEASE_FEED_TRANSPORT_FAILED",
    "RELEASE_FEED_UNAVAILABLE",
    "RELEASE_INDEX_PATH",
    "ReleaseFeedProjection",
    "ReleaseFeedReadError",
    "fetch_release_document",
    "release_feed_projection",
    "release_feed_rollout_enabled",
    "release_feed_target",
    "reset_release_feed_cache_for_tests",
]
