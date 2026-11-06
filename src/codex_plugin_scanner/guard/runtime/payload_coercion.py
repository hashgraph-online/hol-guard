"""Shared payload coercion helpers for JSON-ish object fields."""

from __future__ import annotations

from collections.abc import Mapping
from typing import cast


def object_map(value: object) -> dict[str, object] | None:
    """Return a str-keyed dict view, rejecting non-dicts and non-str keys."""

    if not isinstance(value, dict):
        return None
    raw = cast(dict[object, object], value)
    if not all(isinstance(key, str) for key in raw):
        return None
    return {cast(str, key): item for key, item in raw.items()}


def object_list(value: object) -> list[object] | None:
    if not isinstance(value, list):
        return None
    return cast(list[object], value)


def string_tuple(value: object) -> tuple[str, ...]:
    items = object_list(value)
    if items is None:
        return ()
    return tuple(item for item in items if isinstance(item, str))


def required_string(payload: Mapping[str, object], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{key} must be a non-empty string")
    return value


def optional_string(payload: Mapping[str, object], key: str) -> str | None:
    value = payload.get(key)
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError(f"{key} must be a string or null")
    return value
