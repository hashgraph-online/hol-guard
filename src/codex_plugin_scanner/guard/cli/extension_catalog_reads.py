"""CLI catalog reads: bounded v2 pages first, v1 only when v2 is absent.

These helpers are transport and presentation. The daemon's native read model
owns selection, paging and cursors; the CLI only walks complete traversals
and shapes output. The v1 full catalog is used solely when the daemon reports
that it does not serve v2 (``CatalogV2UnsupportedError``); authentication,
schema, limit and server errors propagate unchanged.
"""

from __future__ import annotations

from urllib.parse import quote_plus

from ..daemon.catalog_v2_client import (
    CatalogV2Client,
    CatalogV2UnsupportedError,
    extension_route,
    v1_extension_from_v2,
)
from ..daemon.client import GuardDaemonRequestError, GuardSurfaceDaemonClient

CATALOG_LIST_SCHEMA = "guard.cli.extension-catalog-list.v2"
_NOT_FOUND = {"catalog_extension_not_found", "catalog_route_not_found"}
# Mirrors the native read model's search-text bound; longer text is not sent.
_MAX_SEARCH_CHARS = 256
# Encoded ``q`` budget inside the 2048-byte raw query cap, leaving room for
# ``limit`` and a cursor. Text that does not fit is filtered locally instead.
_MAX_SEARCH_ENCODED_BYTES = 1900


def catalog_reader(client: object) -> CatalogV2Client | None:
    return CatalogV2Client(client) if isinstance(client, GuardSurfaceDaemonClient) else None


def _v1_extensions(client: GuardSurfaceDaemonClient) -> list[dict[str, object]]:
    extensions = client.extension_control_catalog().get("extensions")
    if not isinstance(extensions, list):
        raise ValueError("daemon returned an invalid catalog")
    return [extension for extension in extensions if isinstance(extension, dict)]


def catalog_list(client: GuardSurfaceDaemonClient) -> dict[str, object]:
    """Every extension's index summary; the full v1 catalog on older daemons."""

    reader = catalog_reader(client)
    if reader is not None:
        try:
            index = reader.traverse("index", item_key="extension_id")
        except CatalogV2UnsupportedError:
            pass
        else:
            return {
                "schema_version": CATALOG_LIST_SCHEMA,
                "native_catalog_digest": index.native_catalog_digest,
                "snapshot_id": index.snapshot_id,
                "total_count": index.total_count,
                "extensions": index.items,
            }
    return client.extension_control_catalog()


def catalog_show(client: GuardSurfaceDaemonClient, target_id: str) -> dict[str, object]:
    """One extension in the v1 shape, read through bounded detail and collections."""

    reader = catalog_reader(client)
    if reader is not None:
        try:
            return v1_extension_from_v2(reader, target_id)
        except CatalogV2UnsupportedError:
            pass
        except GuardDaemonRequestError as error:
            if error.code in _NOT_FOUND:
                raise ValueError(f"unknown extension target: {target_id}") from error
            raise
    for extension in _v1_extensions(client):
        if extension.get("extension_id") == target_id:
            return extension
    raise ValueError(f"unknown extension target: {target_id}")


def pattern_extensions(client: GuardSurfaceDaemonClient, tool: str | None, query: str = "") -> list[dict[str, object]]:
    """Extensions with ``extension_id``, ``name`` and candidate ``permissions``.

    Without ``tool``, the native read model's permission search narrows the
    candidates to permissions containing every term of ``query``. That is a
    superset of the CLI's own phrase match, which the caller still applies, so
    output is unchanged; only fewer permissions cross the wire.
    """

    reader = catalog_reader(client)
    if reader is not None:
        try:
            return _v2_pattern_extensions(reader, tool, query)
        except CatalogV2UnsupportedError:
            pass
    return [
        extension
        for extension in _v1_extensions(client)
        if tool is None or str(extension.get("extension_id", "")) == tool
    ]


def _v2_pattern_extensions(reader: CatalogV2Client, tool: str | None, query: str) -> list[dict[str, object]]:
    if tool is None:
        return _v2_permission_search(reader, query)
    try:
        detail = reader.get(extension_route(tool)).get("extension")
    except GuardDaemonRequestError as error:
        if error.code in _NOT_FOUND:
            return []
        raise
    if not isinstance(detail, dict) or not isinstance(detail.get("extension_id"), str):
        return []
    extension_id = detail["extension_id"]
    permissions = (
        reader.traverse(extension_route(extension_id, "permissions"), item_key="permission_id").items
        if detail.get("permission_count") != 0
        else []
    )
    return [{"extension_id": extension_id, "name": detail.get("name", ""), "permissions": permissions}]


def _v2_permission_search(reader: CatalogV2Client, query: str) -> list[dict[str, object]]:
    index = reader.traverse("index", item_key="extension_id").items
    text = query.strip()
    sendable = (
        text
        and len(text) <= _MAX_SEARCH_CHARS
        and text.isprintable()
        and len(quote_plus(text)) <= _MAX_SEARCH_ENCODED_BYTES
    )
    matches = reader.traverse("permissions", item_key="permission_id", params={"q": text} if sendable else None).items
    grouped: dict[str, list[dict[str, object]]] = {}
    for permission in matches:
        grouped.setdefault(str(permission.get("extension_id", "")), []).append(permission)
    extensions: list[dict[str, object]] = []
    for summary in index:
        extension_id = summary.get("extension_id")
        if isinstance(extension_id, str) and extension_id in grouped:
            extensions.append(
                {"extension_id": extension_id, "name": summary.get("name", ""), "permissions": grouped[extension_id]}
            )
    return extensions


__all__ = ["CATALOG_LIST_SCHEMA", "catalog_list", "catalog_reader", "catalog_show", "pattern_extensions"]
