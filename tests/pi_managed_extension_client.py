"""Writes the managed Pi extension reference into a settings file for tests."""

from __future__ import annotations

import json
from pathlib import Path


def enable_managed_extension(*, settings_path: Path, extension_path: Path) -> None:
    destination = settings_path.expanduser()
    if destination.name != "settings.json" or destination.is_symlink():
        raise ValueError("managed extension settings path is invalid")
    destination.parent.mkdir(parents=True, exist_ok=True)
    payload = json.loads(destination.read_text(encoding="utf-8")) if destination.is_file() else {}
    entries = [item for item in payload.get("extensions", []) if isinstance(item, str) and item != str(extension_path)]
    payload["extensions"] = [*entries, str(extension_path)]
    destination.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
