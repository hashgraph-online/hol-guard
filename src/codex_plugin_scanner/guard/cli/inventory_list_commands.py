"""``hol-guard extensions list`` and ``hol-guard mcp list``: read local state.

``extensions list`` reads the inventory table fleet posture reports from, so what it
prints is what Guard can send to Guard Cloud. ``mcp list`` reads the connector store
the Protect page reads, so the two always agree. Nothing is written and nothing is sent.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
from typing import TYPE_CHECKING, TextIO

from ..runtime.connector_setup_items import connector_setup_href, connector_setup_summary
from ..runtime.fleet_posture_inventory import reportable_inventory_rows

if TYPE_CHECKING:
    from ..store import GuardStore

# Guard command name -> (parser attribute naming the subcommand, inventory kind, kinds listed).
_LIST_COMMANDS: dict[str, tuple[str, str, frozenset[str]]] = {
    "extensions": ("extension_builder_command", "extensions", frozenset({"plugin"})),
    "mcp": ("mcp_command", "mcp", frozenset({"mcp_server"})),
}


def configure_inventory_list_parser(parser: argparse.ArgumentParser) -> None:
    """Arguments shared by ``extensions list`` and ``mcp list``."""

    from .commands_parser_helpers import _add_guard_common_args

    _add_guard_common_args(parser)
    parser.add_argument("--json", action="store_true")


def is_inventory_list_command(args: argparse.Namespace) -> bool:
    spec = _LIST_COMMANDS.get(str(getattr(args, "guard_command", "")))
    return spec is not None and getattr(args, spec[0], None) == "list"


def _text(value: object) -> str | None:
    return value if isinstance(value, str) and value else None


def inventory_list_payload(
    store: GuardStore,
    *,
    command: str,
    generated_at: str,
) -> dict[str, object]:
    """Reported inventory items for ``command`` (``extensions`` or ``mcp``), sorted by harness and name.

    Selection is ``reportable_inventory_rows``, the same function fleet posture sends from.
    """

    _, kind, reported_kinds = _LIST_COMMANDS[command]
    items: list[dict[str, object]] = []
    for selected in reportable_inventory_rows(store.list_inventory()):
        if selected.kind not in reported_kinds:
            continue
        row = selected.row
        items.append(
            {
                "name": selected.name,
                "harness": selected.harness,
                "artifact_type": str(row.get("artifact_type") or ""),
                "source_scope": _text(row.get("source_scope")),
                "config_path": selected.config_path,
                "artifact_hash": _text(row.get("artifact_hash")),
                "policy_action": _text(row.get("last_policy_action")),
                "first_seen_at": selected.first_seen_at,
                "last_seen_at": selected.last_seen_at,
            }
        )
    items.sort(key=lambda item: (str(item["harness"]), str(item["name"]), str(item["config_path"] or "")))
    return {"generated_at": generated_at, "kind": kind, "count": len(items), "items": items}


_STATE_ORDER = {"needs_setup": 0, "allowed": 1, "blocked": 2}


def mcp_list_payload(store: GuardStore, *, generated_at: str, dashboard_url: str | None) -> dict[str, object]:
    """MCP servers as the Protect page lists them, grouped by what they need."""

    items: list[dict[str, object]] = []
    for item in connector_setup_summary(store).items:
        if item.surface != "mcp":
            continue
        status = "needs_setup" if item.needs_setup else item.state
        if status not in _STATE_ORDER:
            continue
        items.append(
            {
                "cli_id": item.cli_id,
                "name": item.name,
                "status": status,
                "source_label": item.source_label,
                "remote_origin": item.remote_origin,
                "declared_sources": list(item.declared_sources),
                "setup_url": connector_setup_href(dashboard_url, item.cli_id),
            }
        )
    items.sort(key=lambda entry: (_STATE_ORDER[str(entry["status"])], str(entry["name"]).lower(), str(entry["cli_id"])))
    counts = {status: sum(1 for entry in items if entry["status"] == status) for status in _STATE_ORDER}
    return {
        "generated_at": generated_at,
        "kind": "mcp",
        "count": len(items),
        "counts": counts,
        "protect_url": connector_setup_href(dashboard_url),
        "items": items,
    }


def run_inventory_list_command(
    args: argparse.Namespace,
    *,
    store: GuardStore,
    output_stream: TextIO | None = None,
) -> int:
    from .render import emit_guard_payload

    command = str(args.guard_command)
    generated_at = datetime.now(timezone.utc).isoformat()
    if command == "mcp":
        from ..daemon.runtime_peer import load_guard_daemon_endpoint_url

        payload = mcp_list_payload(
            store,
            generated_at=generated_at,
            dashboard_url=load_guard_daemon_endpoint_url(store.guard_home),
        )
    else:
        payload = inventory_list_payload(store, command=command, generated_at=generated_at)
    emit_guard_payload(f"{command}.list", payload, bool(getattr(args, "json", False)), output_stream)
    return 0


__all__ = [
    "configure_inventory_list_parser",
    "inventory_list_payload",
    "is_inventory_list_command",
    "mcp_list_payload",
    "run_inventory_list_command",
]
