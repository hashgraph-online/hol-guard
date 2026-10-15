"""Authenticated HTTP adapter for ``/v2/extension-controls/catalog/*`` (ADR 0014).

The caller has already authenticated the request. This adapter forwards the raw
route suffix, query string and ``If-None-Match`` value to the native read model
and writes its bytes verbatim. A missing native read model answers 501 so a
client may fall back to the legacy v1 catalog.

Rollback: ``HOL_GUARD_CATALOG_READ_V2=off`` makes every v2 route answer that
same 501 without dispatching to the native read model, so current clients use
the bounded legacy path. Stage A budgets, Cloud v1 metadata and native
enforcement are unaffected.
"""

from __future__ import annotations

import os
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Protocol

from ..native_catalog_read import NativeCatalogReadResult, native_catalog_read

CATALOG_V2_PREFIX = "/v2/extension-controls/catalog/"
CATALOG_V2_UNAVAILABLE = "catalog_read_model_unavailable"
# Revalidate every use; the representation is immutable for a snapshot but the
# client must still reauthenticate on each request.
CATALOG_V2_CACHE_CONTROL = "private, no-cache"
CATALOG_V2_EXPOSED_HEADERS = "ETag"
CATALOG_V2_ROLLOUT_ENV = "HOL_GUARD_CATALOG_READ_V2"
_DISABLED_VALUES = frozenset({"0", "off", "false", "disabled"})


def catalog_read_v2_enabled(environ: Mapping[str, str] = os.environ) -> bool:
    """The v2 read path is on unless the rollback switch turns it off."""
    return environ.get(CATALOG_V2_ROLLOUT_ENV, "").strip().lower() not in _DISABLED_VALUES


class CatalogReadHandler(Protocol):
    def write_catalog_v2_body(self, body: bytes, *, status: int, headers: dict[str, str]) -> None: ...

    def write_catalog_v2_empty(self, *, status: int, headers: dict[str, str]) -> None: ...

    def write_catalog_v2_error(self, error_code: str, *, status: int) -> None: ...


def serve_catalog_read_v2(
    handler: CatalogReadHandler,
    *,
    path: str,
    query: str,
    if_none_match: str | None,
    guard_home: Path,
    catalog_digest: str,
    reader: Callable[..., NativeCatalogReadResult | None] = native_catalog_read,
) -> None:
    if not catalog_read_v2_enabled():
        handler.write_catalog_v2_error(CATALOG_V2_UNAVAILABLE, status=501)
        return
    route = path.removeprefix(CATALOG_V2_PREFIX)
    result = reader(
        guard_home=guard_home,
        route=route,
        query=query,
        if_none_match=if_none_match,
        expected_catalog_digest=catalog_digest,
    )
    if result is None:
        handler.write_catalog_v2_error(CATALOG_V2_UNAVAILABLE, status=501)
        return
    if result.error_code is not None:
        handler.write_catalog_v2_error(result.error_code, status=result.status)
        return
    headers = {
        "Cache-Control": CATALOG_V2_CACHE_CONTROL,
        "ETag": result.etag or "",
        "Access-Control-Expose-Headers": CATALOG_V2_EXPOSED_HEADERS,
    }
    if result.status == 304:
        handler.write_catalog_v2_empty(status=304, headers=headers)
        return
    if result.body is None:
        handler.write_catalog_v2_error(CATALOG_V2_UNAVAILABLE, status=501)
        return
    handler.write_catalog_v2_body(result.body, status=200, headers=headers)


__all__ = [
    "CATALOG_V2_PREFIX",
    "CATALOG_V2_ROLLOUT_ENV",
    "CATALOG_V2_UNAVAILABLE",
    "catalog_read_v2_enabled",
    "serve_catalog_read_v2",
]
