"""Typed client for the bounded v2 catalog read model (ADR 0014).

Transport and presentation only. The daemon's native read model owns
filtering, paging, cursors and ETags; this module issues requests, handles
200/304 distinctly, verifies traversal integrity and reports protocol absence
so callers can fall back to the v1 catalog. It never filters, pages or
searches catalog content itself.
"""

from __future__ import annotations

import hashlib
import http.client
import time
import urllib.error
from collections import OrderedDict
from dataclasses import dataclass
from urllib.parse import quote, urlencode

from .client import (
    GuardDaemonRequestError,
    GuardDaemonResponseSchemaError,
    GuardDaemonTimeoutError,
    GuardDaemonTransportError,
    GuardSurfaceDaemonClient,
)

CATALOG_V2_PATH = "/v2/extension-controls/catalog/"
MAX_CATALOG_V2_PAGE_BYTES = 262_144
MAX_CATALOG_V2_PAGE_ITEMS = 100
# A traversal of the largest admitted collection (4,096 rules) needs at most
# 4,096 single-item pages; anything beyond these bounds is a daemon fault.
MAX_TRAVERSAL_PAGES = 4_096
MAX_TRAVERSAL_BYTES = 64 * 1024 * 1024
_MAX_CACHE_ENTRIES = 256
_DEFAULT_TIMEOUT_S = 5.0
# Only these answers mean "this daemon has no v2 read model": an older daemon
# answers a bare 404, a newer one without native support answers 501.
_UNSUPPORTED = {(404, None), (404, "not_found"), (501, "catalog_read_model_unavailable")}
_SNAPSHOT_EXPIRED = "catalog_snapshot_expired"


class CatalogV2UnsupportedError(GuardDaemonRequestError):
    """The daemon does not serve the v2 read model; v1 fallback is allowed."""


class CatalogTraversalError(GuardDaemonRequestError):
    """A multi-page traversal could not be verified as complete and consistent."""


@dataclass(frozen=True, slots=True)
class CatalogV2Response:
    status: int
    etag: str | None
    payload: dict[str, object] | None
    size: int


@dataclass(frozen=True, slots=True)
class CatalogTraversal:
    snapshot_id: str
    native_catalog_digest: str
    total_count: int
    items: list[dict[str, object]]


class CatalogV2Client:
    """Authenticated v2 catalog reads with a small validator cache.

    The cache is owned by one client instance, so it is partitioned by daemon
    URL and auth token; the key also binds both explicitly.
    """

    def __init__(self, client: GuardSurfaceDaemonClient, *, timeout: float = _DEFAULT_TIMEOUT_S) -> None:
        self._client = client
        self._timeout = timeout
        token_tag = hashlib.sha256(client.auth_token.encode("utf-8")).hexdigest()[:16]
        self._scope = f"{client.daemon_url}|{token_tag}|"
        self._cache: OrderedDict[str, tuple[str, dict[str, object], int]] = OrderedDict()

    def get(self, route: str, query: str = "") -> dict[str, object]:
        """Return the current representation, revalidating any cached copy."""

        return self._get_sized(route, query)[0]

    def _get_sized(self, route: str, query: str) -> tuple[dict[str, object], int]:
        key = f"{self._scope}{route}?{query}"
        cached = self._cache.get(key)
        response = self._request(route, query, if_none_match=cached[0] if cached else None)
        if response.status == 304:
            if cached is not None and response.etag == cached[0]:
                self._cache.move_to_end(key)
                return cached[1], cached[2]
            # A 304 we cannot satisfy locally gets exactly one unconditional retry.
            response = self._request(route, query, if_none_match=None)
            if response.status != 200:
                raise GuardDaemonResponseSchemaError("Guard daemon answered 304 to an unconditional request")
        payload, etag = response.payload, response.etag
        if payload is None or etag is None:
            raise GuardDaemonResponseSchemaError("Guard daemon catalog response is missing its validator")
        self._cache[key] = (etag, payload, response.size)
        self._cache.move_to_end(key)
        while len(self._cache) > _MAX_CACHE_ENTRIES:
            self._cache.popitem(last=False)
        return payload, response.size

    def traverse(self, route: str, *, item_key: str, params: dict[str, str] | None = None) -> CatalogTraversal:
        """Read every page of one resource, restarting once if the snapshot changes."""

        try:
            return self._traverse_once(route, item_key=item_key, params=params or {})
        except CatalogTraversalError as error:
            if error.code != _SNAPSHOT_EXPIRED:
                raise
        return self._traverse_once(route, item_key=item_key, params=params or {})

    def _traverse_once(self, route: str, *, item_key: str, params: dict[str, str]) -> CatalogTraversal:
        items: list[dict[str, object]] = []
        seen_items: set[str] = set()
        seen_cursors: set[str] = set()
        snapshot_id: str | None = None
        digest: str | None = None
        total_count: int | None = None
        cursor: str | None = None
        consumed_bytes = 0
        for _ in range(MAX_TRAVERSAL_PAGES):
            query_params = {"limit": str(MAX_CATALOG_V2_PAGE_ITEMS), **params}
            if cursor is not None:
                query_params["cursor"] = cursor
            try:
                page, size = self._get_sized(route, urlencode(sorted(query_params.items())))
            except CatalogV2UnsupportedError:
                raise
            except GuardDaemonRequestError as error:
                if error.code == _SNAPSHOT_EXPIRED:
                    raise CatalogTraversalError(str(error), status=error.status, code=_SNAPSHOT_EXPIRED) from error
                raise
            consumed_bytes += size
            if consumed_bytes > MAX_TRAVERSAL_BYTES:
                raise CatalogTraversalError("Guard daemon catalog traversal exceeded its byte budget")
            page_snapshot, page_digest, page_total, page_items, next_cursor = _page_fields(page)
            if snapshot_id is None:
                snapshot_id, digest, total_count = page_snapshot, page_digest, page_total
            elif (page_snapshot, page_digest, page_total) != (snapshot_id, digest, total_count):
                raise CatalogTraversalError("Guard daemon catalog snapshot changed", code=_SNAPSHOT_EXPIRED)
            for item in page_items:
                identity = item.get(item_key)
                if not isinstance(identity, str) or identity in seen_items:
                    raise CatalogTraversalError("Guard daemon catalog traversal returned a duplicate item")
                seen_items.add(identity)
                items.append(item)
            if next_cursor is None:
                if total_count is None or len(items) != total_count or digest is None:
                    raise CatalogTraversalError("Guard daemon catalog traversal was incomplete")
                return CatalogTraversal(snapshot_id, digest, total_count, items)
            if next_cursor in seen_cursors or not page_items:
                raise CatalogTraversalError("Guard daemon catalog traversal did not advance")
            seen_cursors.add(next_cursor)
            cursor = next_cursor
        raise CatalogTraversalError("Guard daemon catalog traversal exceeded its page budget")

    def _request(self, route: str, query: str, *, if_none_match: str | None) -> CatalogV2Response:
        client = self._client
        deadline = time.monotonic() + self._timeout
        headers = {"X-Guard-Token": client.auth_token}
        if if_none_match is not None:
            headers["If-None-Match"] = if_none_match
        path = f"{CATALOG_V2_PATH}{route}" + (f"?{query}" if query else "")
        try:
            with client.open_get(path, headers, timeout=self._timeout) as response:
                raw = client._read_response_with_deadline(
                    response, deadline=deadline, max_bytes=MAX_CATALOG_V2_PAGE_BYTES
                )
                etag = response.headers.get("ETag")
                return CatalogV2Response(200, etag, client._decode_json_response(raw.decode("utf-8")), len(raw))
        except urllib.error.HTTPError as error:
            if error.code == 304:
                etag = error.headers.get("ETag")
                error.close()
                return CatalogV2Response(304, etag, None, 0)
            failure = client._http_request_error(error, deadline=deadline)
            if (failure.status, failure.code) in _UNSUPPORTED:
                raise CatalogV2UnsupportedError(
                    "Guard daemon does not serve the v2 catalog", status=failure.status, code=failure.code
                ) from error
            raise failure from error
        except GuardDaemonRequestError:
            raise
        except UnicodeDecodeError as error:
            raise GuardDaemonResponseSchemaError("Guard daemon response schema is invalid") from error
        except TimeoutError as error:
            raise GuardDaemonTimeoutError("Guard daemon request timed out") from error
        except urllib.error.URLError as error:
            if isinstance(error.reason, TimeoutError):
                raise GuardDaemonTimeoutError("Guard daemon request timed out") from error
            raise GuardDaemonTransportError("Guard daemon request failed") from error
        except (OSError, http.client.HTTPException) as error:
            raise GuardDaemonTransportError("Guard daemon request failed") from error


def _page_fields(page: dict[str, object]) -> tuple[str, str, int, list[dict[str, object]], str | None]:
    snapshot_id = page.get("snapshot_id")
    digest = page.get("native_catalog_digest")
    total_count = page.get("total_count")
    items = page.get("items")
    next_cursor = page.get("next_cursor")
    if (
        not isinstance(snapshot_id, str)
        or not isinstance(digest, str)
        or type(total_count) is not int
        or not isinstance(items, list)
        or not all(isinstance(item, dict) for item in items)
        or not (next_cursor is None or isinstance(next_cursor, str))
    ):
        raise GuardDaemonResponseSchemaError("Guard daemon catalog page schema is invalid")
    return snapshot_id, digest, total_count, items, next_cursor


def extension_route(extension_id: str, collection: str | None = None) -> str:
    route = f"extensions/{quote(extension_id, safe='')}"
    return f"{route}/{collection}" if collection else route


def v1_extension_from_v2(reader: CatalogV2Client, extension_id: str) -> dict[str, object]:
    """Assemble the legacy v1 extension object from bounded v2 reads.

    Presentation only: the result reproduces the v1 shape for CLI output by
    combining one detail read with complete collection traversals. Every
    traversal must come from the detail read's snapshot and match its declared
    count; a changed snapshot restarts the whole assembly once.
    """

    try:
        return _assemble_v1_extension(reader, extension_id)
    except CatalogTraversalError as error:
        if error.code != _SNAPSHOT_EXPIRED:
            raise
    return _assemble_v1_extension(reader, extension_id)


def _assemble_v1_extension(reader: CatalogV2Client, extension_id: str) -> dict[str, object]:
    detail = reader.get(extension_route(extension_id))
    extension = detail.get("extension")
    collections = detail.get("collections")
    snapshot = (detail.get("snapshot_id"), detail.get("native_catalog_digest"))
    if not isinstance(extension, dict) or not isinstance(collections, dict):
        raise GuardDaemonResponseSchemaError("Guard daemon catalog detail schema is invalid")
    result = {key: value for key, value in extension.items() if key not in {"catalog_defaults", "content_revision"}}
    defaults = extension.get("catalog_defaults")
    if not isinstance(defaults, dict) or "enabled" not in defaults or "activation" not in defaults:
        raise GuardDaemonResponseSchemaError("Guard daemon catalog detail schema is invalid")
    result["enabled"] = defaults["enabled"]
    result["activation"] = defaults["activation"]

    def collection(name: str, route: str, item_key: str) -> list[dict[str, object]]:
        declared = collections.get(name)
        if not isinstance(declared, dict) or type(declared.get("total_count")) is not int:
            raise GuardDaemonResponseSchemaError("Guard daemon catalog detail schema is invalid")
        traversal = reader.traverse(extension_route(extension_id, route), item_key=item_key)
        if (traversal.snapshot_id, traversal.native_catalog_digest) != snapshot:
            raise CatalogTraversalError("Guard daemon catalog snapshot changed", code=_SNAPSHOT_EXPIRED)
        if traversal.total_count != declared["total_count"]:
            raise CatalogTraversalError("Guard daemon catalog collection does not match its detail")
        return traversal.items

    result["permissions"] = collection("permissions", "permissions", "permission_id")
    result["rules"] = collection("rules", "rules", "rule_id")
    if "mcp_tools" in collections:
        result["mcp_tools"] = collection("mcp_tools", "mcp-tools", "name")
    return result


__all__ = [
    "CatalogTraversal",
    "CatalogTraversalError",
    "CatalogV2Client",
    "CatalogV2UnsupportedError",
    "extension_route",
    "v1_extension_from_v2",
]
