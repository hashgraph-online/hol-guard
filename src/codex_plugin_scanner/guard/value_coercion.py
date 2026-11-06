"""Small deterministic coercions shared by presentation surfaces."""

from __future__ import annotations

import math


def coerce_int(value: object) -> int:
    """Return a finite integer representation, defaulting invalid input to zero."""

    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            return 0
        return int(value)
    if isinstance(value, str):
        stripped = value.strip()
        if not stripped:
            return 0
        try:
            return int(stripped)
        except ValueError:
            return 0
    return 0


def coerce_non_negative_int(value: object) -> int:
    """Coerce an integer-like value to a non-negative integer, defaulting to zero."""

    if isinstance(value, bool):
        return 0
    if isinstance(value, int):
        return max(0, value)
    if isinstance(value, str) and value.strip():
        try:
            return max(0, int(value.strip()))
        except ValueError:
            return 0
    return 0


__all__ = ["coerce_int", "coerce_non_negative_int"]
