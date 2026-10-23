"""Standard-library-only bounded JSON shared by scoring and local providers."""
from __future__ import annotations

import hashlib
import json
import math
from typing import Any

MAX_RECORD_BYTES = 16 * 1024 * 1024
MAX_DEPTH = 32
MAX_NODES = 500_000


class ContractError(ValueError):
    """Invalid, incompatible, or unbounded public benchmark data."""


def _bounded(value: Any) -> None:
    pending = [(value, 0)]
    nodes = 0
    while pending:
        item, depth = pending.pop()
        nodes += 1
        if depth > MAX_DEPTH or nodes > MAX_NODES:
            raise ContractError("record exceeds depth/node limit")
        if type(item) is dict:
            if any(type(key) is not str for key in item):
                raise ContractError("object keys must be strings")
            pending.extend((v, depth + 1) for v in item.values())
        elif type(item) is list:
            pending.extend((v, depth + 1) for v in item)
        elif type(item) is float:
            if not math.isfinite(item):
                raise ContractError("non-finite numbers are forbidden")
        elif item is not None and type(item) not in (str, bool, int):
            raise ContractError("record must contain only JSON data")


def canonical_json(value: Any) -> str:
    _bounded(value)
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    if len(encoded.encode("utf-8")) > MAX_RECORD_BYTES:
        raise ContractError("record exceeds byte limit")
    return encoded


def digest(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def strict_json_loads(raw: str | bytes) -> Any:
    """Decode bounded inert JSON, rejecting ambiguous or nonfinite values."""
    if len(raw.encode("utf-8") if isinstance(raw, str) else raw) > MAX_RECORD_BYTES:
        raise ContractError("record exceeds byte limit")

    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ContractError(f"duplicate object key: {key}")
            result[key] = value
        return result

    def constant(value):
        raise ContractError(f"non-finite number: {value}")

    try:
        value = json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise ContractError(f"invalid JSON: {exc}") from exc
    canonical_json(value)
    return value
