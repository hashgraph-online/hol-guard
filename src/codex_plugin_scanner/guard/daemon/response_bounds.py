"""Deadline and closure probes for blocking urllib daemon response reads."""

from __future__ import annotations

import io
from typing import Protocol


class _ReadableResponse(Protocol):
    def read(self, n: int = -1, /) -> bytes: ...


def _bound_response_read(response: object, timeout: float) -> bool:
    """Apply a socket deadline before a blocking urllib response read."""

    if isinstance(response, io.BytesIO):
        return True
    candidates: list[object] = [response]
    seen: set[int] = set()
    while candidates and len(seen) < 12:
        candidate = candidates.pop(0)
        if id(candidate) in seen:
            continue
        seen.add(id(candidate))
        if isinstance(candidate, io.BytesIO):
            return True
        set_timeout = getattr(candidate, "settimeout", None)
        if callable(set_timeout):
            set_timeout(timeout)
            return True
        for attribute in ("fp", "raw", "_sock", "sock", "socket"):
            nested = getattr(candidate, attribute, None)
            if nested is not None:
                candidates.append(nested)
    return False


def _response_is_closed(response: object) -> bool:
    candidates: list[object] = [response]
    seen: set[int] = set()
    while candidates and len(seen) < 12:
        candidate = candidates.pop(0)
        if id(candidate) in seen:
            continue
        seen.add(id(candidate))
        is_closed = getattr(candidate, "isclosed", None)
        if callable(is_closed) and is_closed() is True:
            return True
        for attribute in ("fp", "raw"):
            nested = getattr(candidate, attribute, None)
            if nested is not None:
                candidates.append(nested)
    return False
