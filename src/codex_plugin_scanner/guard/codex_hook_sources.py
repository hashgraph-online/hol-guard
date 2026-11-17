"""Strict source loading for Codex hook inventory and activation."""

from __future__ import annotations

from pathlib import Path

from .codex_hook_inventory import (
    CODEX_HOOK_INVENTORY_SOURCE_DUPLICATE,
    CODEX_HOOK_INVENTORY_SOURCE_MALFORMED,
)


def parse_toml_object(data: bytes | None, *, path: Path, label: str) -> dict[str, object]:
    """Parse the captured TOML bytes without reopening the config path."""
    if data is None:
        return {}
    from .codex_config import TomlRefusedError, loads_toml

    try:
        payload = loads_toml(data.decode("utf-8"))
    except (UnicodeDecodeError, TomlRefusedError) as exc:
        reason = (
            CODEX_HOOK_INVENTORY_SOURCE_DUPLICATE
            if isinstance(exc, TomlRefusedError) and exc.reason == "duplicate_key"
            else CODEX_HOOK_INVENTORY_SOURCE_MALFORMED
        )
        raise RuntimeError(
            f"{reason}: Guard could not parse {label} at {path}. Repair the TOML before retrying install."
        ) from exc
    if not isinstance(payload, dict):
        raise RuntimeError(
            f"{CODEX_HOOK_INVENTORY_SOURCE_MALFORMED}: Guard refused to overwrite non-object {label} at {path}."
        )
    return payload
