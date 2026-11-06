"""Deterministic JSON serialization helpers."""

from __future__ import annotations

import json


def stable_json_serialize(value: object) -> str:
    """Serialize nested JSON-compatible values with stable object key order."""

    if isinstance(value, list):
        return f"[{','.join(stable_json_serialize(item) for item in value)}]"
    if isinstance(value, dict):
        return (
            "{"
            + ",".join(
                f"{json.dumps(key, separators=(',', ':'), ensure_ascii=False)}:{stable_json_serialize(value[key])}"
                for key in sorted(value)
            )
            + "}"
        )
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False)
