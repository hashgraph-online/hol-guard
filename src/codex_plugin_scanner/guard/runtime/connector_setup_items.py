"""The connector list Protect shows, shared by the CLI read surfaces.

``hol-guard mcp list``, ``status`` and ``doctor`` read the same observation
store and the same filter as the local dashboard, so a connector that needs
setup is counted once and the counts match the Protect page.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING
from urllib.parse import quote

if TYPE_CHECKING:
    from ..store import GuardStore

_SETUP_SURFACES = frozenset({"mcp", "cli"})


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

    def in_state(self, state: str, surface: str | None = None) -> tuple[ConnectorSetupItem, ...]:
        return tuple(
            item
            for item in self.items
            if item.state == state and not item.needs_setup and surface in {None, item.surface}
        )


def listed_public_items(store: GuardStore) -> list[dict[str, object]]:
    """Stored connectors as the local-CLI API lists them.

    A legacy server-wide MCP record is hidden once a host connection for the
    same server is recorded; package scripts whose manifest is gone drop out.
    """

    # Package script memory loads the command catalog; importing it here keeps
    # `hol-guard --help` from paying for it.
    from .package_json_script_memory import _package_item_available, public_local_cli_item

    stored = store.list_local_cli_items()
    configured = {
        (item.get("server_identity_hash"), item.get("server_command"), item.get("server_args_hash"))
        for item in stored
        if item.get("surface") == "mcp" and item.get("identity_hash") != item.get("server_identity_hash")
    }
    return [
        public_local_cli_item(item)
        for item in stored
        if _package_item_available(item)
        and not (
            item.get("surface") == "mcp"
            and isinstance(item.get("server_identity_hash"), str)
            and item.get("cli_id") == f"local-cli.mcp-{str(item.get('server_identity_hash'))[:8]}"
            and item.get("identity_hash") == item.get("server_identity_hash")
            and (item.get("server_identity_hash"), item.get("server_command"), item.get("server_args_hash"))
            in configured
        )
    ]


def connector_needs_setup(item: Mapping[str, object]) -> bool:
    """Mirror of the dashboard's needs-review rule for one listed connector."""

    if item.get("stale") is True or item.get("state") == "unset":
        return True
    catalog = item.get("mcp_catalog")
    if not isinstance(catalog, Mapping):
        return False
    changes = catalog.get("changes")
    changed = isinstance(changes, Mapping) and any(changes.get(key) for key in ("added", "changed"))
    return catalog.get("stale") is True or catalog.get("complete") is False or changed


def workspace_items(items: Sequence[Mapping[str, object]]) -> list[Mapping[str, object]]:
    """Mirror of the dashboard's Protect workspace filter, without catalog seeds."""

    return [
        item
        for item in items
        if item.get("state") != "unset" or (item.get("suggestable") is True and item.get("surface") in _SETUP_SURFACES)
    ]


def connector_setup_summary(store: GuardStore) -> ConnectorSetupSummary:
    rows: list[ConnectorSetupItem] = []
    for item in workspace_items(listed_public_items(store)):
        cli_id = item.get("cli_id")
        name = item.get("display_name") or item.get("name")
        surface = item.get("surface")
        state = item.get("state")
        if not isinstance(cli_id, str) or not isinstance(name, str) or not isinstance(surface, str):
            continue
        label = item.get("source_label")
        origin = item.get("remote_origin")
        declared = item.get("declared_sources")
        rows.append(
            ConnectorSetupItem(
                cli_id=cli_id,
                name=name,
                surface=surface,
                state=state if isinstance(state, str) else "unset",
                source_label=label if isinstance(label, str) and label else None,
                remote_origin=origin if isinstance(origin, str) and origin else None,
                needs_setup=connector_needs_setup(item),
                declared_sources=tuple(value for value in declared if isinstance(value, str))
                if isinstance(declared, list)
                else (),
            )
        )
    return ConnectorSetupSummary(items=tuple(rows))


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
