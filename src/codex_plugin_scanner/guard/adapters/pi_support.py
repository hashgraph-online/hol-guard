"""Support helpers for the Pi harness adapter."""

from __future__ import annotations

import json
from pathlib import Path

from .pi_extension_source import managed_extension_source as managed_extension_source

PI_DIR = ".pi"
PI_AGENT_DIR = ".pi/agent"
OMP_DIR = ".omp"
OMP_AGENT_DIR = ".omp/agent"
PI_SETTINGS_FILE = "settings.json"
PI_MANAGED_EXTENSION_NAME = "hol-guard.ts"
REMOTE_RESOURCE_PREFIXES = ("npm:", "git:", "http://", "https://", "ssh://")


def json_payload(path: Path) -> dict[str, object]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def is_remote_resource(value: str) -> bool:
    return value.startswith(REMOTE_RESOURCE_PREFIXES)


def enable_managed_extension(*, settings_path: Path, extension_path: Path) -> None:
    destination = settings_path.expanduser()
    if destination.name != PI_SETTINGS_FILE or destination.is_symlink():
        raise ValueError("managed extension settings path is invalid")
    destination.parent.mkdir(parents=True, exist_ok=True)
    payload = json_payload(destination) if destination.is_file() else {}
    rendered = managed_extension_settings(payload, settings_path=destination, extension_path=extension_path)
    destination.write_bytes(rendered)  # NOSONAR - selected settings.json, not a request path


def managed_extension_settings(payload: dict[str, object], *, settings_path: Path, extension_path: Path) -> bytes:
    """Render the managed reference without publishing extension or settings files."""

    payload = dict(payload)
    raw_extensions = payload.get("extensions")
    extensions = [item for item in raw_extensions if isinstance(item, str)] if isinstance(raw_extensions, list) else []
    extension_value = str(extension_path)
    extensions = [
        item
        for item in extensions
        if item == extension_value or not _is_managed_extension_reference(item, settings_path=settings_path)
    ]
    if extension_value not in extensions:
        extensions.append(extension_value)
    payload["extensions"] = extensions
    return (json.dumps(payload, indent=2) + "\n").encode("utf-8")


def _is_managed_extension_reference(value: str, *, settings_path: Path) -> bool:
    if is_remote_resource(value):
        return False
    candidate = Path(value).expanduser()
    if not candidate.is_absolute():
        candidate = (settings_path.parent / candidate).expanduser()
    return candidate.name == PI_MANAGED_EXTENSION_NAME


def disable_managed_extension(*, settings_path: Path, extension_path: Path) -> None:
    if not settings_path.is_file():
        return
    payload = json_payload(settings_path)
    raw_extensions = payload.get("extensions")
    if not isinstance(raw_extensions, list):
        return
    extension_value = str(extension_path)
    payload["extensions"] = [item for item in raw_extensions if isinstance(item, str) and item != extension_value]
    settings_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
