"""Receipt and policy progress with separate optional telemetry status."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from .policy_sync_status import sync_output_rows


def render_sync_summary(console: Console, payload: dict[str, object]) -> None:
    body = Table.grid(padding=(0, 1))
    for label, value in sync_output_rows(payload):
        body.add_row(label, value)
    degraded = payload.get("telemetry_status") == "degraded"
    if degraded:
        body.add_row("Telemetry", "uploads delayed")
    elif payload.get("telemetry_status") == "paused":
        body.add_row("Telemetry", "uploads paused")
    console.print(Panel(body, title="Guard sync complete", border_style="yellow" if degraded else "green"))
