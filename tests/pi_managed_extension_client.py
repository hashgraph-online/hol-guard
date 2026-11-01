"""Writes the managed Pi extension reference into a settings file for tests."""

from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.adapters.pi_support import (
    PI_SETTINGS_FILE,
    json_payload,
    managed_extension_settings,
)


def enable_managed_extension(*, settings_path: Path, extension_path: Path) -> None:
    destination = settings_path.expanduser()
    if destination.name != PI_SETTINGS_FILE or destination.is_symlink():
        raise ValueError("managed extension settings path is invalid")
    destination.parent.mkdir(parents=True, exist_ok=True)
    payload = json_payload(destination) if destination.is_file() else {}
    rendered = managed_extension_settings(payload, settings_path=destination, extension_path=extension_path)
    destination.write_bytes(rendered)  # NOSONAR - selected settings.json, not a request path
