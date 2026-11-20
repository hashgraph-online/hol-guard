"""The connector list Protect shows, shared by the CLI read surfaces.

``hol-guard mcp list``, ``status`` and ``doctor`` read the same observation
store and the same filter as the local dashboard, so a connector that needs
setup is counted once and the counts match the Protect page. The runtime
(``connector_setup_rows.rs``) owns that filter and the needs-setup rule.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, cast
from urllib.parse import quote

if TYPE_CHECKING:
    from ..store import GuardStore


@dataclass(frozen=True, slots=True)
class ConnectorSetupItem:
    cli_id: str
    name: str
    surface: str
    state: str
    source_label: str | None
    remote_origin: str | None
    needs_setup: bool
    declared_sources: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ConnectorSetupSummary:
    items: tuple[ConnectorSetupItem, ...]

    def needing_setup(self, surface: str | None = None) -> tuple[ConnectorSetupItem, ...]:
        return tuple(item for item in self.items if item.needs_setup and surface in {None, item.surface})


def listed_public_items(store: GuardStore) -> list[dict[str, object]]:
    """Stored connectors as the local-CLI API lists them.

    A legacy server-wide MCP record is hidden once a host connection for the
    same server is recorded; package scripts whose manifest is gone drop out.
    """

    # Package script memory loads the command catalog; importing it here keeps
    # `hol-guard --help` from paying for it.
    from .package_json_script_memory import package_items_available, public_local_cli_item

    stored = store.list_local_cli_items()
    configured = {
        (item.get("server_identity_hash"), item.get("server_command"), item.get("server_args_hash"))
        for item in stored
        if item.get("surface") == "mcp" and item.get("identity_hash") != item.get("server_identity_hash")
    }
    shown = package_items_available(stored)
    return [
        public_local_cli_item(item)
        for item, keep in zip(stored, shown, strict=True)
        if keep
        and not (
            item.get("surface") == "mcp"
            and isinstance(item.get("server_identity_hash"), str)
            and item.get("cli_id") == f"local-cli.mcp-{str(item.get('server_identity_hash'))[:8]}"
            and item.get("identity_hash") == item.get("server_identity_hash")
            and (item.get("server_identity_hash"), item.get("server_command"), item.get("server_args_hash"))
            in configured
        )
    ]


_ITEM_KEYS = "cli_id display_name name surface state suggestable stale source_label remote_origin declared_sources"
_ROW_TYPES: dict[str, type | tuple[type, ...]] = {
    "cli_id": str,
    "name": str,
    "surface": str,
    "state": str,
    "source_label": (str, type(None)),
    "remote_origin": (str, type(None)),
    "needs_setup": bool,
    "declared_sources": list,
}


def _setup_fields(item: dict[str, object]) -> dict[str, object]:
    """The fields the setup check reads; command catalogs stay out of the request."""

    fields: dict[str, object] = {key: item[key] for key in _ITEM_KEYS.split() if key in item}
    catalog = item.get("mcp_catalog")
    if isinstance(catalog, dict):
        changes = cast("dict[str, object]", catalog).get("changes")
        sliced = {key: catalog[key] for key in ("stale", "complete") if key in catalog}
        if isinstance(changes, dict):
            sliced["changes"] = {key: bool(changes[key]) for key in ("added", "changed") if key in changes}
        fields["mcp_catalog"] = sliced
    return fields


def connector_setup_summary(store: GuardStore) -> ConnectorSetupSummary:
    """Protect's connectors, filtered and checked for setup by the runtime."""

    from ..native_runner_authority import NativeRunnerAuthorityError, native_runner_authority

    items = [_setup_fields(item) for item in listed_public_items(store)]
    rows = native_runner_authority("connector_setup_rows", {"items": items}, guard_home=store.guard_home).get("rows")
    checked = cast("list[dict[str, Any]]", rows if isinstance(rows, list) else [None])
    for row in checked:
        if not (
            isinstance(row, dict)
            and set(row) == set(_ROW_TYPES)
            and all(isinstance(row[key], kind) for key, kind in _ROW_TYPES.items())
            and all(isinstance(value, str) for value in row["declared_sources"])
        ):
            raise NativeRunnerAuthorityError("native_runner_authority_result_invalid")
    return ConnectorSetupSummary(
        items=tuple(
            ConnectorSetupItem(**cast("dict[str, Any]", {**row, "declared_sources": tuple(row["declared_sources"])}))
            for row in checked
        )
    )


def connector_setup_href(dashboard_url: str | None, cli_id: str | None = None) -> str | None:
    """Protect deep link on the local dashboard; ``None`` when it is not running."""

    if not dashboard_url:
        return None
    base = dashboard_url.rstrip("/")
    if cli_id is None:
        return f"{base}/extensions"
    return f"{base}/extensions/local-cli/{quote(cli_id, safe='')}"


def connector_setup_status(store: GuardStore, dashboard_url: str | None) -> dict[str, object] | None:
    """Counts for the status and doctor line; ``None`` when the store cannot be read."""

    try:
        summary = connector_setup_summary(store)
    except (OSError, RuntimeError, TypeError, ValueError, KeyError, sqlite3.Error):
        return None
    mcp = len(summary.needing_setup("mcp"))
    cli = len(summary.needing_setup("cli"))
    return {
        "needing_setup": len(summary.needing_setup()),
        "mcp_servers": mcp,
        "local_clis": cli,
        "url": connector_setup_href(dashboard_url),
    }
