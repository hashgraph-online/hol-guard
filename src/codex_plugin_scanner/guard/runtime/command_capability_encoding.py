"""Canonical encoding and bounded state shape for local command grants."""

from __future__ import annotations

import json
from collections.abc import Mapping


def canonical_bytes(payload: Mapping[str, object]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def state_items(payload: object) -> list[dict[str, object]]:
    if not isinstance(payload, dict):
        return []
    raw_items = payload.get("items")
    if not isinstance(raw_items, list):
        return []
    return [{str(key): value for key, value in item.items()} for item in raw_items if isinstance(item, dict)]
