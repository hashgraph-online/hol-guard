"""Strict paging over the native store's workspace fix proposal reads.

Every answer must have exactly the expected shape. A malformed page raises
instead of being read as an empty listing.
"""

from __future__ import annotations

from typing import Any, Final

# A runaway store cannot keep a listing loop going forever.
_MAX_PAGES: Final = 4096


def native_pages(
    store: Any,
    method: str,
    args: dict[str, object],
    cursor_name: str,
    fields: frozenset[str],
    *,
    limit: int | None = None,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    cursor: object = None
    for _ in range(_MAX_PAGES):
        page_args = dict(args)
        if cursor is not None:
            page_args[cursor_name] = cursor
        answer = store._native_store_call(method, page_args)
        if not isinstance(answer, dict) or set(answer) != {"items", "next"}:
            raise RuntimeError(f"native {method} returned no answer")
        items, cursor = answer["items"], answer["next"]
        if not isinstance(items, list) or (cursor is not None and not items):
            raise RuntimeError(f"native {method} returned no answer")
        rows.extend(native_row(item, fields, method) for item in items)
        if limit is not None and len(rows) >= limit:
            return rows[:limit]
        if cursor is None:
            return rows
    raise RuntimeError(f"native {method} kept paging")


def native_row(value: object, fields: frozenset[str], method: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise RuntimeError(f"native {method} returned no answer")
    return {str(key): item for key, item in value.items()}


def native_text(value: object, method: str) -> str:
    if not isinstance(value, str):
        raise RuntimeError(f"native {method} returned no answer")
    return value


__all__ = ["native_pages", "native_row", "native_text"]
