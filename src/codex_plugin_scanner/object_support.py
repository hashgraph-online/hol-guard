"""Shared validation helpers for untrusted object payloads."""

from __future__ import annotations

from typing import cast


def string_keyed_mapping(value: object) -> dict[str, object] | None:
    """Return a string-keyed copy when ``value`` is a compatible mapping."""

    if not isinstance(value, dict):
        return None
    mapping = cast(dict[object, object], value)
    if not all(isinstance(key, str) for key in mapping):
        return None
    return {cast(str, key): item for key, item in mapping.items()}
