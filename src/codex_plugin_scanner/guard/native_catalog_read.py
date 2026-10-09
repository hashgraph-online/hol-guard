"""Thin resident transport for the native catalog read model (ADR 0014).

Rust owns snapshot construction, filtering, paging, cursors, ETags and
serialization. Python only bounds the raw request strings, forwards them over
the existing resident protocol and validates the result frame. It never
parses, filters, pages or re-serializes catalog content: ``body`` is written
to the HTTP client exactly as Rust produced it.
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass
from pathlib import Path

from .native_resident_client import native_resident_client_request
from .native_runtime import _isolated_environment, native_runtime_status
from .native_runtime_resilience import native_record_resident_failure, native_record_resident_success

CATALOG_READ_FEATURE = "catalog-read-model-v1"
MAX_CATALOG_V2_BODY_BYTES = 262_144
MAX_CATALOG_V2_ROUTE_BYTES = 512
MAX_CATALOG_V2_QUERY_BYTES = 2048
MAX_CATALOG_V2_IF_NONE_MATCH_BYTES = 2048
_RESIDENT_PROTOCOL_FEATURE = "resident-protocol-v2"
_REQUEST_SCHEMA = "guard-catalog-read-request.v1"
_RESULT_SCHEMA = "guard-catalog-read-result.v1"
_RESULT_FIELDS = frozenset({"schema", "outcome", "http_status", "etag", "body", "error_code"})
_ETAG = re.compile(r'"cr1-[0-9a-f]{32}"')
_DIGEST = re.compile(r"[0-9a-f]{64}")
_ERROR_STATUS = {
    "catalog_request_invalid": 400,
    "catalog_query_invalid": 400,
    "catalog_cursor_invalid": 400,
    "catalog_route_not_found": 404,
    "catalog_extension_not_found": 404,
    "catalog_snapshot_expired": 409,
    "catalog_item_exceeds_page_budget": 500,
    "catalog_snapshot_mismatch": 503,
    "catalog_read_model_unavailable": 503,
}


@dataclass(frozen=True, slots=True)
class NativeCatalogReadResult:
    status: int
    etag: str | None = None
    body: bytes | None = None
    error_code: str | None = None


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate native response field")
        result[key] = value
    return result


def _validated_result(decoded: object) -> NativeCatalogReadResult | None:
    if not isinstance(decoded, dict) or set(decoded) != _RESULT_FIELDS or decoded["schema"] != _RESULT_SCHEMA:
        return None
    outcome, status, etag = decoded["outcome"], decoded["http_status"], decoded["etag"]
    body, error_code = decoded["body"], decoded["error_code"]
    if outcome == "ok":
        if status != 200 or not isinstance(etag, str) or not _ETAG.fullmatch(etag) or error_code is not None:
            return None
        if not isinstance(body, str):
            return None
        encoded = body.encode("utf-8")
        if len(encoded) > MAX_CATALOG_V2_BODY_BYTES:
            return None
        return NativeCatalogReadResult(status=200, etag=etag, body=encoded)
    if outcome == "not_modified":
        if status != 304 or not isinstance(etag, str) or not _ETAG.fullmatch(etag):
            return None
        if body is not None or error_code is not None:
            return None
        return NativeCatalogReadResult(status=304, etag=etag)
    if outcome == "error":
        if not isinstance(error_code, str) or _ERROR_STATUS.get(error_code) != status:
            return None
        if etag is not None or body is not None:
            return None
        return NativeCatalogReadResult(status=status, error_code=error_code)
    return None


def native_catalog_read_available() -> bool:
    status = native_runtime_status()
    if not status.available or not status.compatible or status.identity is None or status.capabilities is None:
        return False
    features = set(status.capabilities.features)
    return _RESIDENT_PROTOCOL_FEATURE in features and CATALOG_READ_FEATURE in features


def native_catalog_read(
    *,
    guard_home: Path,
    route: str,
    query: str,
    if_none_match: str | None,
    expected_catalog_digest: str,
    timeout_seconds: float = 2.0,
) -> NativeCatalogReadResult | None:
    """Return the native result, or ``None`` when the read model is unavailable.

    ``None`` means protocol absence (no native runtime, no capability, transport
    or frame failure); callers answer 501 so clients may use the v1 route.
    """

    if len(route.encode("utf-8")) > MAX_CATALOG_V2_ROUTE_BYTES:
        return NativeCatalogReadResult(status=404, error_code="catalog_route_not_found")
    if len(query.encode("utf-8")) > MAX_CATALOG_V2_QUERY_BYTES:
        return NativeCatalogReadResult(status=400, error_code="catalog_query_invalid")
    if if_none_match is not None and len(if_none_match.encode("utf-8")) > MAX_CATALOG_V2_IF_NONE_MATCH_BYTES:
        # An oversized validator never matches; send the full representation.
        if_none_match = None
    if not _DIGEST.fullmatch(expected_catalog_digest):
        return None
    status = native_runtime_status()
    if not native_catalog_read_available() or status.identity is None:
        return None
    envelope = {
        "operation": "catalog_read",
        "request": {
            "schema": _REQUEST_SCHEMA,
            "route": route,
            "query": query,
            "if_none_match": if_none_match,
            "expected_catalog_digest": expected_catalog_digest,
        },
        "deadline_budget_ms": max(1, int(timeout_seconds * 1000)),
    }
    payload = json.dumps(envelope, separators=(",", ":")).encode("utf-8")
    response = native_resident_client_request(
        executable=status.identity.path,
        guard_home=guard_home,
        environment=_isolated_environment(),
        payload=payload,
        timeout_seconds=timeout_seconds,
        deadline_monotonic=time.monotonic() + timeout_seconds,
    )
    if response is None:
        native_record_resident_failure(status.identity.sha256, guard_home, reason="native_catalog_read_transport")
        return None
    try:
        decoded = json.loads(response.decode("utf-8"), object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, ValueError):
        native_record_resident_failure(status.identity.sha256, guard_home, reason="native_catalog_read_malformed")
        return None
    result = _validated_result(decoded)
    if result is None:
        native_record_resident_failure(status.identity.sha256, guard_home, reason="native_catalog_read_schema")
        return None
    native_record_resident_success(status.identity.sha256, guard_home)
    return result


__all__ = [
    "CATALOG_READ_FEATURE",
    "MAX_CATALOG_V2_BODY_BYTES",
    "NativeCatalogReadResult",
    "native_catalog_read",
    "native_catalog_read_available",
]
