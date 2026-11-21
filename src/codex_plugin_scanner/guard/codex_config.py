"""Wire form for Codex payloads handed to the native runtime."""

from __future__ import annotations

import json
import math
from collections.abc import Mapping, Sequence
from datetime import date, datetime, time
from typing import Any
from uuid import uuid4

# The range the native ``codex_hook_identity`` op takes as a JSON integer.
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
    the native ``codex_hook_identity`` op takes. Equal meanings share a token, so the
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
