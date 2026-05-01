"""OpenClaw configuration loading helpers."""

from __future__ import annotations

import json
import re
from pathlib import Path

_MAX_INCLUDE_DEPTH = 8
_CONFIG_SUFFIXES = {".json", ".json5", ".yaml", ".yml"}


def load_config(path: Path) -> dict[str, object]:
    return _load_config(path, seen=set(), depth=0)


def _load_config(path: Path, *, seen: set[Path], depth: int) -> dict[str, object]:
    if depth > _MAX_INCLUDE_DEPTH:
        return {}
    try:
        resolved_path = path.resolve()
    except (OSError, RuntimeError):
        return {}
    if resolved_path in seen:
        return {}
    try:
        raw = resolved_path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return {}
    payload = _parse_config_payload(raw)
    if not isinstance(payload, dict):
        return {}
    return _resolve_includes(resolved_path, payload, seen={*seen, resolved_path}, depth=depth)


def _resolve_includes(path: Path, payload: dict[str, object], *, seen: set[Path], depth: int) -> dict[str, object]:
    include_value = payload.get("$include")
    include_paths = _include_paths(path.parent, include_value)
    merged: dict[str, object] = {}
    for include_path in include_paths:
        included_payload = _load_config(include_path, seen=seen, depth=depth + 1)
        merged = _deep_merge(merged, included_payload)
    local_payload = {key: value for key, value in payload.items() if key != "$include"}
    return _deep_merge(merged, local_payload)


def _include_paths(base_dir: Path, value: object) -> tuple[Path, ...]:
    values = value if isinstance(value, list) else [value]
    paths: list[Path] = []
    for item in values:
        if not isinstance(item, str) or not item.strip():
            continue
        candidate = Path(item.strip()).expanduser()
        path = candidate if candidate.is_absolute() else base_dir / candidate
        if path.suffix.lower() in _CONFIG_SUFFIXES:
            paths.append(path)
    return tuple(paths)


def _deep_merge(base: dict[str, object], overlay: dict[str, object]) -> dict[str, object]:
    result = dict(base)
    for key, value in overlay.items():
        existing = result.get(key)
        if isinstance(existing, dict) and isinstance(value, dict):
            result[key] = _deep_merge(existing, value)
        else:
            result[key] = value
    return result


def _parse_config_payload(raw: str) -> object:
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        pass
    stripped = _strip_json_comments(raw)
    normalized = _strip_trailing_json_commas(stripped)
    try:
        return json.loads(normalized)
    except json.JSONDecodeError:
        pass
    json5_normalized = _strip_trailing_json_commas(
        _convert_single_quoted_strings(_quote_unquoted_object_keys(stripped))
    )
    try:
        return json.loads(json5_normalized)
    except json.JSONDecodeError:
        return {}


def _strip_json_comments(text: str) -> str:
    output: list[str] = []
    quote: str | None = None
    escape = False
    in_line_comment = False
    in_block_comment = False
    index = 0
    while index < len(text):
        char = text[index]
        next_char = text[index + 1] if index + 1 < len(text) else ""
        if in_line_comment:
            if char == "\n":
                in_line_comment = False
                output.append(char)
            index += 1
            continue
        if in_block_comment:
            if char == "*" and next_char == "/":
                in_block_comment = False
                index += 2
                continue
            if char == "\n":
                output.append(char)
            index += 1
            continue
        if quote is not None:
            output.append(char)
            if escape:
                escape = False
            elif char == "\\":
                escape = True
            elif char == quote:
                quote = None
            index += 1
            continue
        if char in {"'", '"'}:
            quote = char
            output.append(char)
            index += 1
            continue
        if char == "/" and next_char == "/":
            in_line_comment = True
            index += 2
            continue
        if char == "/" and next_char == "*":
            in_block_comment = True
            index += 2
            continue
        output.append(char)
        index += 1
    return "".join(output)


def _strip_trailing_json_commas(text: str) -> str:
    output: list[str] = []
    quote: str | None = None
    escape = False
    index = 0
    while index < len(text):
        char = text[index]
        if quote is not None:
            output.append(char)
            if escape:
                escape = False
            elif char == "\\":
                escape = True
            elif char == quote:
                quote = None
            index += 1
            continue
        if char in {"'", '"'}:
            quote = char
            output.append(char)
            index += 1
            continue
        if char == ",":
            lookahead = index + 1
            while lookahead < len(text) and text[lookahead] in " \t\r\n":
                lookahead += 1
            if lookahead < len(text) and text[lookahead] in "}]":
                index += 1
                continue
        output.append(char)
        index += 1
    return "".join(output)


def _quote_unquoted_object_keys(text: str) -> str:
    output: list[str] = []
    quote: str | None = None
    escape = False
    expecting_key = False
    index = 0
    while index < len(text):
        char = text[index]
        if quote is not None:
            output.append(char)
            if escape:
                escape = False
            elif char == "\\":
                escape = True
            elif char == quote:
                quote = None
            index += 1
            continue
        if char in {"'", '"'}:
            quote = char
            output.append(char)
            index += 1
            continue
        if char in "{,":
            expecting_key = True
            output.append(char)
            index += 1
            continue
        if expecting_key and char.isspace():
            output.append(char)
            index += 1
            continue
        if expecting_key and _starts_identifier(char):
            match = re.match(r"[A-Za-z_$][A-Za-z0-9_$-]*", text[index:])
            if match is not None:
                key = match.group(0)
                lookahead = index + len(key)
                while lookahead < len(text) and text[lookahead].isspace():
                    lookahead += 1
                if lookahead < len(text) and text[lookahead] == ":":
                    output.append(json.dumps(key))
                    index += len(key)
                    expecting_key = False
                    continue
        expecting_key = False
        output.append(char)
        index += 1
    return "".join(output)


def _convert_single_quoted_strings(text: str) -> str:
    output: list[str] = []
    quote: str | None = None
    escape = False
    index = 0
    while index < len(text):
        char = text[index]
        if quote == "'":
            if escape:
                _append_single_quote_escape(output, char)
                escape = False
            elif char == "\\":
                escape = True
            elif char == "'":
                quote = None
                output.append('"')
            elif char == '"':
                output.append('\\"')
            else:
                output.append(char)
            index += 1
            continue
        if quote == '"':
            output.append(char)
            if escape:
                escape = False
            elif char == "\\":
                escape = True
            elif char == '"':
                quote = None
            index += 1
            continue
        if char == "'":
            quote = "'"
            output.append('"')
            index += 1
            continue
        if char == '"':
            quote = '"'
        output.append(char)
        index += 1
    return "".join(output)


def _append_single_quote_escape(output: list[str], char: str) -> None:
    if char == "'":
        output.append("'")
    elif char == '"':
        output.append('\\"')
    elif char == "\\":
        output.append("\\\\")
    elif char in {"b", "f", "n", "r", "t", "/"}:
        output.append(f"\\{char}")
    else:
        output.append(char)


def _starts_identifier(char: str) -> bool:
    return char.isalpha() or char in {"_", "$"}
