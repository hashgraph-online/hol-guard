"""Helpers for Guard-managed Codex MCP configuration."""

from __future__ import annotations

import json
import re
from pathlib import Path

try:
    import tomllib  # type: ignore[attr-defined]
except ModuleNotFoundError:
    import tomli as tomllib  # type: ignore[no-redef]


_BARE_KEY_PATTERN = re.compile(r"^[A-Za-z0-9_-]+$")


def read_toml_payload(path: Path) -> dict[str, object]:
    if not path.is_file():
        return {}
    try:
        with path.open("rb") as handle:
            payload = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def write_toml_payload(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(dump_toml(payload), encoding="utf-8")


def dump_toml(payload: dict[str, object]) -> str:
    lines: list[str] = []
    _emit_table(lines, (), payload)
    rendered = "\n".join(line for line in lines if line is not None).strip()
    return f"{rendered}\n" if rendered else ""


def _emit_table(lines: list[str], path: tuple[str, ...], payload: dict[str, object]) -> None:
    scalar_items = [(key, value) for key, value in payload.items() if value is not None and not isinstance(value, dict)]
    nested_items = [(key, value) for key, value in payload.items() if isinstance(value, dict)]

    if path:
        lines.append(f"[{'.'.join(_format_key(part) for part in path)}]")
    for key, value in scalar_items:
        lines.append(f"{_format_key(key)} = {_format_value(value)}")
    if path and (scalar_items or nested_items):
        lines.append("")

    for index, (key, value) in enumerate(nested_items):
        _emit_table(lines, (*path, key), value)
        if index != len(nested_items) - 1:
            lines.append("")


def _format_key(key: str) -> str:
    if _BARE_KEY_PATTERN.fullmatch(key):
        return key
    return json.dumps(key)


def _format_value(value: object) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int | float):
        return str(value)
    if isinstance(value, str):
        return json.dumps(value)
    if isinstance(value, dict):
        return _format_inline_table(value)
    if isinstance(value, list):
        return "[" + ", ".join(_format_value(item) for item in value) + "]"
    if isinstance(value, tuple):
        return "[" + ", ".join(_format_value(item) for item in value) + "]"
    return json.dumps(str(value))


def _format_inline_table(value: dict[object, object]) -> str:
    items = []
    for key, item in value.items():
        if not isinstance(key, str):
            continue
        items.append(f"{_format_key(key)} = {_format_value(item)}")
    return "{ " + ", ".join(items) + " }" if items else "{}"
