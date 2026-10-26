"""Shared readers for Guard-managed harness state and backup files."""

from __future__ import annotations

import json
from pathlib import Path


def load_backup_payload(backup_path: Path) -> dict[str, str | bool | None]:
    """Load the stable Guard backup envelope without raising on corrupt state."""

    try:
        text = backup_path.read_text(encoding="utf-8")
    except OSError:
        return {"readable": False, "existed": False, "content": None}
    return parse_backup_payload(text)


def parse_backup_payload(text: str) -> dict[str, str | bool | None]:
    """Decode a captured backup generation without consulting the filesystem."""
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return {"readable": False, "existed": False, "content": None}
    if not isinstance(payload, dict):
        return {"readable": False, "existed": False, "content": None}
    existed = payload.get("existed") is True
    content = payload.get("content")
    return {
        "readable": True,
        "existed": existed,
        "content": content if isinstance(content, str) else None,
    }


def load_string_state_payload(
    state_path: Path,
    *,
    keys: tuple[str, ...] = ("managed_config_path", "backup_path", "scope", "workspace_dir"),
) -> dict[str, str]:
    """Load the string-valued fields understood by managed-install adapters."""

    if not state_path.is_file():
        return {}
    try:
        payload = json.loads(state_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    if not isinstance(payload, dict):
        return {}
    return {key: value for key in keys if isinstance((value := payload.get(key)), str)}
