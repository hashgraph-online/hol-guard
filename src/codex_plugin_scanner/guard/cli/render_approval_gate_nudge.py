"""Render the advisory approval-gate nudge in status and doctor output."""

from __future__ import annotations

from typing import cast

from rich.console import Console
from rich.markup import escape


def print_approval_gate_nudge(console: Console, payload: dict[str, object]) -> None:
    raw_gate = payload.get("approval_gate")
    if not isinstance(raw_gate, dict):
        return
    gate = cast(dict[str, object], raw_gate)
    if gate.get("status") != "not_set":
        return
    nudge = gate.get("nudge")
    setup = gate.get("setup")
    if not isinstance(nudge, str) or not nudge:
        return
    console.print(f"[bold yellow]{escape(nudge)}[/bold yellow]")
    if isinstance(setup, str) and setup:
        console.print(escape(setup))
