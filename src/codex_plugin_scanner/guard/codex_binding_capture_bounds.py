"""Bounded JSON and UTF-8 handling for optional Codex diagnostics."""

from __future__ import annotations

import json
import math
from typing import Final, cast

MAX_CANONICAL_PAYLOAD_BYTES: Final = 64 * 1024
MAX_JSON_DEPTH: Final = 64
MAX_JSON_NODES: Final = 4096
MAX_JSON_STRING_BYTES: Final = 64 * 1024
MAX_JSON_INT_BITS: Final = MAX_JSON_STRING_BYTES * 3


def bounded_utf8_bytes(value: object, *, maximum_bytes: int = MAX_CANONICAL_PAYLOAD_BYTES) -> bytes | None:
    """Return bounded UTF-8 bytes without encoding an oversized string."""

    if type(maximum_bytes) is not int or not 0 < maximum_bytes <= MAX_CANONICAL_PAYLOAD_BYTES:
        return None
    if type(value) is bytes:
        if len(value) > maximum_bytes:
            return None
        try:
            _ = value.decode("utf-8")
        except UnicodeDecodeError:
            return None
        return value
    if type(value) is not str or len(value) > maximum_bytes:
        return None
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError:
        return None
    return encoded if len(encoded) <= maximum_bytes else None


def _walk_json_value(
    value: object,
    *,
    depth: int,
    nodes: list[int],
    active: set[int],
    maximum_bytes: int,
) -> bool:
    if depth > MAX_JSON_DEPTH or nodes[0] >= MAX_JSON_NODES:
        return False
    nodes[0] += 1
    value_type = type(value)
    if value is None or value_type is bool:
        return True
    if value_type is int:
        return cast(int, value).bit_length() <= MAX_JSON_INT_BITS
    if value_type is float:
        return math.isfinite(cast(float, value))
    if value_type is str:
        text = cast(str, value)
        if len(text) > min(MAX_JSON_STRING_BYTES, maximum_bytes):
            return False
        try:
            return len(text.encode("utf-8")) <= maximum_bytes
        except UnicodeEncodeError:
            return False
    if value_type is list:
        identity = id(value)
        if identity in active:
            return False
        active.add(identity)
        try:
            items = cast(list[object], value)
            return all(
                _walk_json_value(
                    item,
                    depth=depth + 1,
                    nodes=nodes,
                    active=active,
                    maximum_bytes=maximum_bytes,
                )
                for item in items
            )
        finally:
            active.remove(identity)
    if value_type is dict:
        identity = id(value)
        if identity in active:
            return False
        active.add(identity)
        try:
            items = cast(dict[object, object], value)
            for key, item in items.items():
                if (
                    type(key) is not str
                    or not _walk_json_value(
                        key,
                        depth=depth + 1,
                        nodes=nodes,
                        active=active,
                        maximum_bytes=maximum_bytes,
                    )
                    or not _walk_json_value(
                        item,
                        depth=depth + 1,
                        nodes=nodes,
                        active=active,
                        maximum_bytes=maximum_bytes,
                    )
                ):
                    return False
            return True
        finally:
            active.remove(identity)
    return False


def validate_json_value(value: object, *, maximum_bytes: int = MAX_CANONICAL_PAYLOAD_BYTES) -> bool:
    """Validate exact JSON builtin types, depth, nodes, strings, and cycles."""

    if type(maximum_bytes) is not int or not 0 < maximum_bytes <= MAX_CANONICAL_PAYLOAD_BYTES:
        return False
    try:
        return _walk_json_value(value, depth=0, nodes=[0], active=set(), maximum_bytes=maximum_bytes)
    except (RecursionError, RuntimeError, UnicodeError, ValueError):
        return False


def canonical_json_bytes(value: object, *, maximum_bytes: int = MAX_CANONICAL_PAYLOAD_BYTES) -> bytes | None:
    """Encode bounded JSON incrementally using the capture canonical form."""

    if not validate_json_value(value, maximum_bytes=maximum_bytes):
        return None
    try:
        encoder = json.JSONEncoder(
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        encoded = bytearray()
        for fragment in encoder.iterencode(value):
            fragment_bytes = fragment.encode("utf-8")
            if len(encoded) + len(fragment_bytes) > maximum_bytes:
                return None
            encoded.extend(fragment_bytes)
        return bytes(encoded)
    except (RecursionError, TypeError, UnicodeError, ValueError, OverflowError):
        return None


__all__ = [
    "MAX_CANONICAL_PAYLOAD_BYTES",
    "MAX_JSON_DEPTH",
    "MAX_JSON_NODES",
    "MAX_JSON_STRING_BYTES",
    "bounded_utf8_bytes",
    "canonical_json_bytes",
    "validate_json_value",
]
