"""Reject ambiguous duplicate JSON object keys in bounded parsers."""

from __future__ import annotations


def unique_json_object(pairs: list[tuple[str, object]], duplicate_error: str = "duplicate key") -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(duplicate_error)
        result[key] = value
    return result
