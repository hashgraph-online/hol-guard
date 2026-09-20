"""values presentation for Guard CLI output."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .render import PayloadDict, Text
    from .render_context import RenderContext


def _status_label(view: RenderContext, detection: dict[str, object]) -> str:
    installed = bool(detection.get("installed"))
    command_available = bool(detection.get("command_available"))
    if installed and command_available:
        return "Ready"
    if installed:
        return "Config only"
    return "Not found"


def _status_text(view: RenderContext, detection: dict[str, object]) -> Text:
    label = view._status_label(detection)
    style = {"Ready": "green", "Config only": "yellow", "Not found": "red"}[label]
    return view.Text(label, style=style)


def _warning_count(view: RenderContext, detection: dict[str, object]) -> int:
    return len(view._coerce_string_list(detection.get("warnings")))


def _bool_label(view: RenderContext, value: bool) -> Text:
    return view.Text("yes" if value else "no", style="green" if value else "red")


def _action_text(view: RenderContext, action: str) -> Text:
    styles = {
        "allow": "green",
        "warn": "yellow",
        "review": "yellow",
        "require-reapproval": "magenta",
        "sandbox-required": "cyan",
        "block": "red",
    }
    return view.Text(action, style=styles.get(action, "white"))


def _command_text(view: RenderContext, command: object) -> str:
    if isinstance(command, list):
        return " ".join(str(item) for item in command)
    return str(command or "none")


def _coerce_object_dict(view: RenderContext, value: object) -> PayloadDict:
    if not isinstance(value, dict):
        return {}
    return {key: item for key, item in value.items() if isinstance(key, str)}


def _coerce_dict_list(view: RenderContext, value: object) -> list[PayloadDict]:
    if not isinstance(value, list):
        return []
    return [view._coerce_object_dict(item) for item in value if isinstance(item, dict)]


def _coerce_string_list(view: RenderContext, value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if isinstance(item, str) and item]


def _short_path(view: RenderContext, value: object) -> str:
    if not isinstance(value, str) or not value:
        return "unknown"
    path = view.Path(value)
    try:
        relative = path.expanduser().resolve().relative_to(view.Path.home().resolve())
    except ValueError:
        parts = path.parts[-3:]
        return str(view.Path(*parts)) if parts else value
    return f"~/{relative}"


def _timestamp_parts(view: RenderContext, value: object) -> tuple[str, str]:
    if not isinstance(value, str) or not value:
        return ("unknown", "--:--")
    normalized = value.replace("T", " ").replace("+00:00", "Z")
    return (normalized[:10], normalized[11:16])


def _clean_terminal_output(view: RenderContext, value: str) -> str:
    return view.re.sub(r"\x1b\[[0-9;?]*[ -/]*[@-~]", "", value)
