"""Shared JSON-object loading for ecosystem discovery."""

from __future__ import annotations

import json
from pathlib import Path


def load_json_object(path: Path) -> dict[str, object]:
    """Load a JSON object, returning an empty mapping for missing or invalid data."""

    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(payload, dict):
            return payload
    except (json.JSONDecodeError, OSError):
        pass
    return {}
