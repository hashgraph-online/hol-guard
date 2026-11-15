"""Strict source loading for Codex hook inventory and activation."""

from __future__ import annotations

import json
from pathlib import Path

from .codex_hook_inventory import (
    CODEX_HOOK_INVENTORY_SOURCE_DUPLICATE,
    CODEX_HOOK_INVENTORY_SOURCE_MALFORMED,
    CODEX_HOOK_INVENTORY_SOURCE_UNREADABLE,
)


class _DuplicateJsonKeyError(ValueError):
    key: str

    def __init__(self, key: str) -> None:
        super().__init__(key)
        self.key = key


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    payload: dict[str, object] = {}
    for key, value in pairs:
        if key in payload:
            raise _DuplicateJsonKeyError(key)
        payload[key] = value
    return payload


def strict_json_object(path: Path, *, label: str) -> dict[str, object]:
    if path.is_symlink() or (path.exists() and not path.is_file()):
        raise RuntimeError(
            f"{CODEX_HOOK_INVENTORY_SOURCE_UNREADABLE}: Guard refused to overwrite non-file {label} at {path}. "
            "Replace it with a readable regular file before retrying install."
        )
    if not path.is_file():
        return {}
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise RuntimeError(
            f"{CODEX_HOOK_INVENTORY_SOURCE_UNREADABLE}: Guard could not read {label} at {path}. Repair file "
            "permissions before retrying install."
        ) from exc
    return parse_json_object(data, path=path, label=label)


def parse_json_object(data: bytes | None, *, path: Path, label: str) -> dict[str, object]:
    """Apply the inventory parser to an already captured source generation."""
    if data is None:
        return {}
    try:
        payload = json.loads(data.decode("utf-8"), object_pairs_hook=_unique_json_object)
    except _DuplicateJsonKeyError as exc:
        raise RuntimeError(
            f"{CODEX_HOOK_INVENTORY_SOURCE_DUPLICATE}: Guard found duplicate key {exc.key!r} in {label} at "
            f"{path}. Remove the duplicate before retrying install."
        ) from exc
    except OSError as exc:
        raise RuntimeError(
            f"{CODEX_HOOK_INVENTORY_SOURCE_UNREADABLE}: Guard could not read {label} at {path}. Repair file "
            "permissions before retrying install."
        ) from exc
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError(
            f"{CODEX_HOOK_INVENTORY_SOURCE_MALFORMED}: Guard refused to overwrite unreadable {label} at {path} "
            "because its JSON is malformed. Repair the JSON before retrying install."
        ) from exc
    if not isinstance(payload, dict):
        raise RuntimeError(
            f"{CODEX_HOOK_INVENTORY_SOURCE_MALFORMED}: Guard refused to overwrite non-object {label} at {path}. "
            "Replace it with a JSON object before retrying install."
        )
    return payload


def strict_toml_object(path: Path, *, label: str) -> dict[str, object]:
    if path.is_symlink() or (path.exists() and not path.is_file()):
        raise RuntimeError(
            f"{CODEX_HOOK_INVENTORY_SOURCE_UNREADABLE}: Guard refused to overwrite non-file {label} at {path}. "
            "Replace it with a readable regular file before retrying install."
        )
    if not path.is_file():
        return {}
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise RuntimeError(
            f"{CODEX_HOOK_INVENTORY_SOURCE_UNREADABLE}: Guard could not read {label} at {path}. Repair file "
            "permissions before retrying install."
        ) from exc
    return parse_toml_object(data, path=path, label=label)


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
