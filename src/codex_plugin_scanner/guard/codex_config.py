"""Helpers for Guard-managed Codex MCP configuration."""

from __future__ import annotations

import importlib
import json
import math
from collections.abc import Mapping, Sequence
from datetime import date, datetime, time
from pathlib import Path
from typing import Any
from uuid import uuid4

tomllib = importlib.import_module("tomllib" if __import__("sys").version_info >= (3, 11) else "tomli")

# Parsing and patching a large hand-written config is file-sized work.
_RENDER_TIMEOUT_SECONDS = 10.0


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
    hand. Pass the text Guard read and the native ``codex_toml_render`` kind
    applies the edit to it instead, leaving every line Guard did not change
    exactly as it was, and checks the result still means the payload.
    """

    # Imported here rather than at module scope: the hook bridge imports this
    # module on every tool call and never renders a config.
    from .native_runner_authority import native_runner_authority

    if isinstance(original, bytes):
        try:
            original = original.decode("utf-8")
        except UnicodeDecodeError:
            original = None
    wire = _Wire(payload)
    answer = native_runner_authority(
        "codex_toml_render",
        {"payload": wire.text(payload), "tokens": wire.meanings, "original": original or None},
        timeout_seconds=_RENDER_TIMEOUT_SECONDS,
    )
    rendered = answer.get("text")
    if not isinstance(rendered, str):
        raise ValueError("Codex config render answer is malformed")
    return rendered


# The range ``native_codex_hook_identity`` sends as a JSON integer.
_EXACT_INT_MIN = -(2**63)
_EXACT_INT_MAX = 2**64 - 1


def _strings_in(value: object, found: set[str]) -> None:
    if isinstance(value, str):
        found.add(value)
    elif isinstance(value, Mapping):
        for key, item in value.items():
            _strings_in(key, found)
            _strings_in(item, found)
    elif isinstance(value, Sequence) and not isinstance(value, bytes | bytearray):
        for item in value:
            _strings_in(item, found)


class _Wire:
    """Order-preserving JSON for payloads read from TOML.

    A scalar JSON cannot carry becomes a token naming its meaning, the form
    ``native_codex_hook_identity`` sends. Equal meanings share a token, so the
    runtime compares tokens as it would the values. ``decode`` maps each token
    back to the value it stood for. The prefix is drawn at random and checked
    against every string the payloads hold.
    """

    def __init__(self, *payloads: object) -> None:
        present: set[str] = set()
        for payload in payloads:
            _strings_in(payload, present)
        prefix = uuid4().hex
        while any(text.startswith(prefix) for text in present):
            prefix = uuid4().hex
        self._prefix = prefix
        self._issued: dict[str, str] = {}
        self._originals: dict[str, object] = {}
        self.meanings: dict[str, object] = {}

    def text(self, value: object) -> str:
        return json.dumps(self._value(value), separators=(",", ":"))

    def decode(self, text: str) -> Any:
        return self._restore(json.loads(text))

    def _token(self, original: object, meaning: dict[str, str]) -> str:
        key = json.dumps(meaning, sort_keys=True)
        token = self._issued.get(key)
        if token is None:
            token = f"{self._prefix}-{len(self.meanings)}"
            self._issued[key] = token
            self._originals[token] = original
            self.meanings[token] = meaning
        return token

    def _string(self, value: str) -> str:
        if value.startswith(self._prefix):
            raise ValueError("A Codex payload string collides with Guard's wire tokens.")
        return value

    def _value(self, value: object) -> object:
        # bool is an int and datetime a date, so each is settled first.
        if value is None or isinstance(value, bool):
            return value
        if isinstance(value, str):
            return self._string(value)
        if isinstance(value, int):
            if _EXACT_INT_MIN <= value <= _EXACT_INT_MAX:
                return value
            return self._token(value, {"__int__": str(value)})
        if isinstance(value, float):
            if math.isfinite(value):
                return value
            return self._token(value, {"type": "float", "value": repr(value)})
        if isinstance(value, Mapping):
            wired: dict[str, object] = {}
            for key, item in value.items():
                if not isinstance(key, str):
                    raise ValueError("Codex payload keys must be strings.")
                wired[self._string(key)] = self._value(item)
            return wired
        if isinstance(value, Sequence) and not isinstance(value, bytes | bytearray):
            return [self._value(item) for item in value]
        if isinstance(value, datetime | date | time):
            return self._token(value, {"type": type(value).__name__, "value": value.isoformat()})
        return self._token(value, {"type": type(value).__name__, "value": repr(value)})

    def _restore(self, value: object) -> object:
        if isinstance(value, str):
            return self._originals.get(value, value)
        if isinstance(value, list):
            return [self._restore(item) for item in value]
        if isinstance(value, dict):
            return {key: self._restore(item) for key, item in value.items()}
        return value
