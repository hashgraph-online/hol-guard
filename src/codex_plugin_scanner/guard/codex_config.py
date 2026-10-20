"""Helpers for Guard-managed Codex MCP configuration."""

from __future__ import annotations

import importlib
import json
import re
from pathlib import Path

tomllib = importlib.import_module("tomllib" if __import__("sys").version_info >= (3, 11) else "tomli")


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


def read_config_bytes(path: Path) -> bytes | None:
    """The file as it stands, for rendering an edit back onto it."""

    try:
        return path.read_bytes()
    except OSError:
        return None


def dump_toml(payload: dict[str, object], *, original: str | bytes | None = None) -> str:
    """Render a Codex config payload, keeping the user's own file where we can.

    Guard reads `config.toml` into a plain dict and writes it back, so without
    `original` an install reflows the whole file: comments gone, keys and tables
    reordered, inline tables and arrays respelled. Codex users write that file by
    hand. Pass the text Guard read and the edit is applied to it instead, leaving
    every line Guard did not change exactly as it was.
    """

    if original:
        preserved = _dump_onto_original(payload, original)
        if preserved is not None:
            return preserved
    lines: list[str] = []
    _emit_table(lines, (), payload)
    rendered = "\n".join(line for line in lines if line is not None).strip()
    return f"{rendered}\n" if rendered else ""


def _dump_onto_original(payload: dict[str, object], original: str | bytes) -> str | None:
    """Apply ``payload`` to the parsed ``original``, or give up and return None.

    The result has to mean exactly what the plain renderer would have written,
    so it is parsed back and compared against the payload before it is used.
    Anything unexpected — a file Guard cannot parse, a value tomlkit will not
    take, a document that no longer reads back as the payload — falls through
    to the plain renderer rather than writing a file nobody has checked.
    """

    # Imported here rather than at module scope: the hook bridge imports this
    # module on every tool call and never renders a config.
    import tomlkit
    from tomlkit.exceptions import TOMLKitError

    expected = _plain_payload(payload)
    if isinstance(original, bytes):
        try:
            original = original.decode("utf-8")
        except UnicodeDecodeError:
            return None
    try:
        document = tomlkit.parse(original)
        _apply_payload(document, payload)
        rendered = tomlkit.dumps(document)
    except (TOMLKitError, TypeError, ValueError):
        return None
    try:
        if not _same_value(tomllib.loads(rendered), expected):
            return None
    except tomllib.TOMLDecodeError:
        return None
    return rendered


def _apply_payload(table: dict[str, object], payload: dict[str, object]) -> None:
    """Make one parsed table match ``payload`` with the fewest edits."""

    for key in [key for key in table if key not in payload or payload[key] is None]:
        del table[key]
    for key, value in payload.items():
        if value is None:
            continue
        existing = table.get(key)
        if isinstance(value, dict) and isinstance(existing, dict):
            _apply_payload(existing, value)
            continue
        replacement = _plain_value(value)
        if isinstance(replacement, list) and isinstance(existing, list):
            _apply_array(existing, replacement)  # pyright: ignore[reportUnknownArgumentType]
            continue
        if key in table and _same_value(_unwrap(existing), replacement):
            # The value Guard wants is already there. Assigning it anyway would
            # respell it and drop whatever comment sits on that line, so don't.
            continue
        table[key] = replacement


def _apply_array(existing: list[object], replacement: list[object]) -> None:
    """Make one parsed array match ``replacement`` without moving comments.

    Hook groups are not stable by position. Install drops Guard's group and
    appends it at the end, so an index match writes the user's group into
    Guard's old table. The user's comments then sit on Guard's values and
    leave with them on uninstall. An element that already has the wanted value
    keeps its parsed item, wherever it sits. Only an element that changed is
    edited in place.
    """

    current_items = list(existing)
    unwrapped = [_unwrap(item) for item in current_items]
    used: set[int] = set()
    kept: list[object | None] = []
    for item in replacement:
        match = next(
            (index for index, current in enumerate(unwrapped) if index not in used and _same_value(current, item)),
            None,
        )
        if match is None:
            kept.append(None)
            continue
        used.add(match)
        kept.append(current_items[match])
    leftovers = [current_items[index] for index in range(len(current_items)) if index not in used]
    rebuilt: list[object] = []
    leftover_index = 0
    for item, kept_item in zip(replacement, kept, strict=True):
        if kept_item is not None:
            rebuilt.append(kept_item)
            continue
        if leftover_index < len(leftovers):
            current = leftovers[leftover_index]
            leftover_index += 1
            if isinstance(item, dict) and isinstance(current, dict):
                _apply_payload(current, item)  # pyright: ignore[reportUnknownArgumentType]
                rebuilt.append(current)
                continue
            if isinstance(item, list) and isinstance(current, list):
                _apply_array(current, item)  # pyright: ignore[reportUnknownArgumentType]
                rebuilt.append(current)
                continue
        rebuilt.append(item)
    existing.clear()
    existing.extend(rebuilt)


def _same_value(left: object, right: object) -> bool:
    """Whether two values are the same, counting ``1`` and ``True`` as different.

    Python reads ``1 == True``, ``0 == False`` and ``30 == 30.0`` as true, so a
    plain comparison lets a user's ``hooks = 1`` stand in for the boolean Guard
    writes: the assignment is skipped, the readback accepts the file, and Codex
    keeps an integer where Guard's own state check looks for ``True`` and
    reports the hooks as disabled.
    """

    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        right_dict: dict[object, object] = right  # pyright: ignore[reportAssignmentType]
        return left.keys() == right_dict.keys() and all(_same_value(left[key], right_dict[key]) for key in left)  # pyright: ignore[reportUnknownArgumentType]
    if isinstance(left, list):
        right_list: list[object] = right  # pyright: ignore[reportAssignmentType]
        return len(left) == len(right_list) and all(_same_value(*pair) for pair in zip(left, right_list, strict=True))  # pyright: ignore[reportUnknownArgumentType]
    return left == right


def _unwrap(value: object) -> object:
    """A parsed value as plain Python, for comparing against a payload value."""

    unwrap = getattr(value, "unwrap", None)
    return unwrap() if callable(unwrap) else value


def _plain_payload(payload: dict[str, object]) -> dict[str, object]:
    return {key: _plain_value(value) for key, value in payload.items() if value is not None}


def _plain_value(value: object) -> object:
    """Normalize a payload value the way the plain renderer writes it."""

    if isinstance(value, dict):
        return _plain_payload(value)  # pyright: ignore[reportUnknownArgumentType]
    if isinstance(value, list | tuple):
        return [_plain_value(item) for item in value]  # pyright: ignore[reportUnknownVariableType]
    return value


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
