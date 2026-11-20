"""``GET /v2/extension-controls/catalog/*`` (ADR 0014), run behind ``desktop library-call``.

The native daemon has already authenticated the caller. This call forwards the
raw route suffix, query string and ``If-None-Match`` value to the native read
model and returns its bytes verbatim as ``{status, etag, body, error}``. A
missing read model answers 501 so a client may fall back to the v1 catalog.

Rollback: ``HOL_GUARD_CATALOG_READ_V2=off`` makes every v2 route answer that
same 501 without dispatching to the native read model.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

from ..store import GuardStore

_UNAVAILABLE = {"status": 501, "etag": None, "body": None, "error": "catalog_read_model_unavailable"}


def catalog_v2(store: GuardStore, args: Mapping[str, Any]) -> dict[str, object]:
    """``route.catalog_v2``: one catalog read-model answer."""

    from .. import native_catalog_read as transport
    from ..extension_control_host import host_for
    from ..library_calls import LibraryCallError

    route = args.get("route")
    query = args.get("query", "")
    if_none_match = args.get("if_none_match")
    if (
        not isinstance(route, str)
        or not isinstance(query, str)
        or not (if_none_match is None or isinstance(if_none_match, str))
    ):
        raise LibraryCallError("invalid_arguments")
    if not transport.catalog_read_v2_enabled():
        return dict(_UNAVAILABLE)
    result = transport.native_catalog_read(
        guard_home=Path(store.guard_home),
        route=route,
        query=query,
        if_none_match=if_none_match,
        expected_catalog_digest=host_for(store).api.catalog_digest,
    )
    if result is None:
        return dict(_UNAVAILABLE)
    if result.error_code is not None:
        return {"status": result.status, "etag": None, "body": None, "error": result.error_code}
    if result.status != 304 and result.body is None:
        return dict(_UNAVAILABLE)
    return {
        "status": result.status,
        "etag": result.etag,
        "body": None if result.body is None else result.body.decode("utf-8"),
        "error": None,
    }


CATALOG_CALLS = {"route.catalog_v2": catalog_v2}
