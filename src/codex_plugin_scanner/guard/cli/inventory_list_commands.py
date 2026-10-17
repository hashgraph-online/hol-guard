"""``hol-guard extensions list`` and ``hol-guard mcp list``: read the local inventory.

Both commands read the same local inventory table that fleet posture reports from, so what
they print is what Guard can send to Guard Cloud. Nothing is written and nothing is sent.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
from typing import TYPE_CHECKING, TextIO

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


def run_inventory_list_command(
    args: argparse.Namespace,
    *,
    store: GuardStore,
    output_stream: TextIO | None = None,
) -> int:
    from .render import emit_guard_payload

    command = str(args.guard_command)
    payload = inventory_list_payload(
        store,
        command=command,
        generated_at=datetime.now(timezone.utc).isoformat(),
    )
    emit_guard_payload(f"{command}.list", payload, bool(getattr(args, "json", False)), output_stream)
    return 0


__all__ = [
    "configure_inventory_list_parser",
    "inventory_list_payload",
    "is_inventory_list_command",
    "run_inventory_list_command",
]
