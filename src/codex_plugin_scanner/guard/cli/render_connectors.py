"""Render connector setup state: ``mcp list`` and the status/doctor line."""

from __future__ import annotations

from typing import cast

from rich import box
from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

_STATUS_LABELS = {"needs_setup": "Needs setup", "allowed": "Allowed", "blocked": "Blocked"}
_STATUS_STYLES = {"needs_setup": "yellow", "allowed": "green", "blocked": "red"}


def _plural(count: int, singular: str, plural: str) -> str:
    return f"{count} {singular if count == 1 else plural}"


def connector_setup_line(summary: object) -> str | None:
    """``Connectors needing setup: N (M MCP servers, K local CLIs) → <link>``, or ``None`` at zero."""

    if not isinstance(summary, dict):
        return None
    fields = cast(dict[str, object], summary)
    total = fields.get("needing_setup")
    mcp = fields.get("mcp_servers")
    cli = fields.get("local_clis")
    if not isinstance(total, int) or total <= 0 or not isinstance(mcp, int) or not isinstance(cli, int):
        return None
    line = (
        f"Connectors needing setup: {total} "
        f"({_plural(mcp, 'MCP server', 'MCP servers')}, {_plural(cli, 'local CLI', 'local CLIs')})"
    )
    url = fields.get("url")
    return f"{line} → {url}" if isinstance(url, str) and url else f"{line} → hol-guard dashboard"


def print_connector_setup_line(console: Console, payload: dict[str, object]) -> None:
    line = connector_setup_line(payload.get("connector_setup"))
    if line is not None:
        console.print(f"[bold yellow]{escape(line)}[/bold yellow]")


def render_mcp_list(console: Console, payload: dict[str, object]) -> None:
    raw_items = payload.get("items")
    listed = raw_items if isinstance(raw_items, list) else []
    items = [cast(dict[str, object], item) for item in listed if isinstance(item, dict)]
    needing = sum(1 for item in items if item.get("status") == "needs_setup")
    console.print(
        Panel.fit(
            f"[bold]MCP servers[/bold]\n{_plural(len(items), 'server', 'servers')} Guard has seen, "
            f"{needing} needing setup",
            border_style="cyan",
        )
    )
    if not items:
        console.print("[dim]Guard has not seen an MCP server in a harness config or a tool call yet.[/dim]")
        return
    table = Table(box=box.SIMPLE_HEAVY, show_header=True)
    table.add_column("Name", style="bold")
    table.add_column("Status")
    table.add_column("Seen in")
    table.add_column("Endpoint")
    for item in items:
        status = str(item.get("status") or "")
        # Connector names, labels and origins come from harness configs: Text keeps them literal.
        table.add_row(
            Text(str(item.get("name") or "unknown")),
            Text(_STATUS_LABELS.get(status, status), style=_STATUS_STYLES.get(status, "")),
            Text(str(item.get("source_label") or "—")),
            Text(str(item.get("remote_origin") or "—")),
        )
    console.print(table)
    links = [item for item in items if item.get("status") == "needs_setup" and isinstance(item.get("setup_url"), str)]
    for item in links:
        console.print(Text(f"Set up {item.get('name')}: {item.get('setup_url')}"))
    if needing and not links:
        console.print("[dim]Run `hol-guard dashboard` to set these up on the Protect page.[/dim]")
