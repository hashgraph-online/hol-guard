"""Small deterministic collection helpers."""

from __future__ import annotations


def dedupe_preserving_order(values: list[str]) -> list[str]:
    """Return the first occurrence of each string in input order."""

    seen: set[str] = set()
    ordered: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        ordered.append(value)
    return ordered
