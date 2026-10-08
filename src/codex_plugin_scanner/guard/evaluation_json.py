"""Shared strict JSON object-pairs validation for evaluation inputs."""

from __future__ import annotations


def reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    """Reject ambiguous object fields before validating an evaluation record."""

    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result
