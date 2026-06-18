"""Rich rendering helpers for Guard self-uninstall output."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from rich.console import Console


def render_self_uninstall(console: Console, payload: dict[str, object]) -> None:
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text

    body = Table.grid(padding=(0, 1))
    body.add_row("Current version", str(payload.get("current_version") or "unknown"))
    body.add_row("Installer", str(payload.get("installer") or "unknown"))
    command = payload.get("command")
    if isinstance(command, list) and command:
        body.add_row("Command", " ".join(str(part) for part in command))
    body.add_row("Dry run", _bool_label(bool(payload.get("dry_run")), text_type=Text))
    planned_harnesses = _coerce_string_list(payload.get("planned_managed_harnesses"))
    if planned_harnesses:
        body.add_row("Planned harness cleanup", str(len(planned_harnesses)))
    planned_shims = _coerce_string_list(payload.get("planned_package_shim_managers"))
    if planned_shims:
        body.add_row("Planned package shims", str(len(planned_shims)))
    if payload.get("oauth_credentials_cleared") is not None:
        body.add_row(
            "Cloud credentials cleared",
            _bool_label(bool(payload.get("oauth_credentials_cleared")), text_type=Text),
        )
    if payload.get("guard_home_removed") is not None:
        body.add_row("Guard home removed", _bool_label(bool(payload.get("guard_home_removed")), text_type=Text))
    if payload.get("message"):
        body.add_row("Message", str(payload.get("message")))
    status = str(payload.get("status") or "unknown")
    border_style = {
        "planned": "blue",
        "pending": "yellow",
        "removed": "green",
        "failed": "red",
    }.get(status, "red")
    console.print(Panel(body, title=f"Guard uninstall: {status}", border_style=border_style))
    notes = _coerce_string_list(payload.get("notes"))
    stdout = str(payload.get("stdout") or "").strip()
    stderr = str(payload.get("stderr") or "").strip()
    error = str(payload.get("error") or "").strip()
    if notes:
        console.print(Panel("\n".join(f"• {note}" for note in notes), title="Notes", border_style="blue"))
    if status == "removed" and stdout:
        console.print(Panel(stdout, title="stdout", border_style="green"))
    if status == "failed" and stdout:
        console.print(Panel(stdout, title="stdout", border_style="yellow"))
    if status == "failed" and stderr:
        console.print(Panel(stderr, title="stderr", border_style="yellow"))
    if error:
        console.print(Panel(error, title="error", border_style="red"))


def _bool_label(value: bool, *, text_type) -> object:
    return text_type("yes" if value else "no", style="green" if value else "red")


def _coerce_string_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if isinstance(item, str) and item]


__all__ = ["render_self_uninstall"]
