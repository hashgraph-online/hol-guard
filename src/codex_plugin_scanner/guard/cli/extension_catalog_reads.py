"""CLI catalog reads: bounded v2 pages first, v1 only when v2 is absent.

These helpers are transport and presentation. The daemon's native read model
owns selection, paging and cursors; the CLI only walks complete traversals
and shapes output. The v1 full catalog is used solely when the daemon reports
that it does not serve v2 (``CatalogV2UnsupportedError``); authentication,
schema, limit and server errors propagate unchanged.
"""

from __future__ import annotations

from ..daemon.catalog_v2_client import (
    CatalogV2Client,
    CatalogV2UnsupportedError,
    extension_route,
    v1_extension_from_v2,
)
from ..daemon.client import GuardDaemonRequestError, GuardSurfaceDaemonClient

CATALOG_LIST_SCHEMA = "guard.cli.extension-catalog-list.v2"
_NOT_FOUND = {"catalog_extension_not_found", "catalog_route_not_found"}


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


def pattern_extensions(client: GuardSurfaceDaemonClient, tool: str | None) -> list[dict[str, object]]:
    """Extensions with ``extension_id``, ``name`` and complete ``permissions``."""

    reader = catalog_reader(client)
    if reader is not None:
        try:
            return _v2_pattern_extensions(reader, tool)
        except CatalogV2UnsupportedError:
            pass
    return [
        extension
        for extension in _v1_extensions(client)
        if tool is None or str(extension.get("extension_id", "")) == tool
    ]


def _v2_pattern_extensions(reader: CatalogV2Client, tool: str | None) -> list[dict[str, object]]:
    if tool is not None:
        try:
            detail = reader.get(extension_route(tool)).get("extension")
        except GuardDaemonRequestError as error:
            if error.code in _NOT_FOUND:
                return []
            raise
        summaries = [detail] if isinstance(detail, dict) else []
    else:
        summaries = reader.traverse("index", item_key="extension_id").items
    extensions: list[dict[str, object]] = []
    for summary in summaries:
        extension_id = summary.get("extension_id")
        if not isinstance(extension_id, str):
            continue
        permissions = (
            reader.traverse(extension_route(extension_id, "permissions"), item_key="permission_id").items
            if summary.get("permission_count") != 0
            else []
        )
        extensions.append({"extension_id": extension_id, "name": summary.get("name", ""), "permissions": permissions})
    return extensions


__all__ = ["CATALOG_LIST_SCHEMA", "catalog_list", "catalog_reader", "catalog_show", "pattern_extensions"]
