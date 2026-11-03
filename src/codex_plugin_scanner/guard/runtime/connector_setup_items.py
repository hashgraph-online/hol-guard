"""The connector list Protect shows, shared by the CLI read surfaces.

``hol-guard mcp list``, ``status`` and ``doctor`` read the same observation
store and the same filter as the local dashboard, so a connector that needs
setup is counted once and the counts match the Protect page. The runtime
(``connector_setup_rows.rs``) owns that filter and the needs-setup rule.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from typing import TYPE_CHECKING, cast
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


def connector_setup_summary(store: GuardStore) -> ConnectorSetupSummary:
    """Protect's connectors, filtered and checked for setup by the runtime."""

    from ..native_runner_authority import NativeRunnerAuthorityError, native_runner_authority

    rows = native_runner_authority(
        "connector_setup_rows", {"items": listed_public_items(store)}, guard_home=store.guard_home
    ).get("rows")
    try:
        items = tuple(
            ConnectorSetupItem(
                cli_id=str(row["cli_id"]),
                name=str(row["name"]),
                surface=str(row["surface"]),
                state=str(row["state"]),
                source_label=cast("str | None", row["source_label"]),
                remote_origin=cast("str | None", row["remote_origin"]),
                needs_setup=row["needs_setup"] is True,
                declared_sources=tuple(str(value) for value in cast("list[object]", row["declared_sources"])),
            )
            for row in cast("list[dict[str, object]]", rows)
        )
    except (KeyError, TypeError) as error:
        raise NativeRunnerAuthorityError("native_runner_authority_result_invalid") from error
    return ConnectorSetupSummary(items=items)


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
