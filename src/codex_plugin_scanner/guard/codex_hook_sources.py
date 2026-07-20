"""Strict source loading for Codex hook inventory and activation."""

from __future__ import annotations

import importlib
import json
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .codex_hook_inventory import (
    CODEX_HOOK_INVENTORY_SOURCE_CHANGED,
    CODEX_HOOK_INVENTORY_SOURCE_DUPLICATE,
    CODEX_HOOK_INVENTORY_SOURCE_MALFORMED,
    CODEX_HOOK_INVENTORY_SOURCE_UNREADABLE,
)

tomllib: Any
if sys.version_info >= (3, 11):
    import tomllib as tomllib  # pyright: ignore[reportMissingImports]
else:  # pragma: no cover - Python 3.10 runtime compatibility
    tomllib = importlib.import_module("tomli")


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
        payload = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_unique_json_object)
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
        with path.open("rb") as handle:
            payload = tomllib.load(handle)
    except OSError as exc:
        raise RuntimeError(
            f"{CODEX_HOOK_INVENTORY_SOURCE_UNREADABLE}: Guard could not read {label} at {path}. Repair file "
            "permissions before retrying install."
        ) from exc
    except tomllib.TOMLDecodeError as exc:
        reason = (
            CODEX_HOOK_INVENTORY_SOURCE_DUPLICATE
            if "overwrite" in str(exc).lower()
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


def require_hook_inventory_sources_unchanged(
    *,
    config_payloads: Mapping[Path, dict[str, object]],
    hook_payloads: Mapping[Path, dict[str, object]],
) -> None:
    for path, expected in config_payloads.items():
        if strict_toml_object(path, label="Codex config file") != expected:
            raise RuntimeError(
                f"{CODEX_HOOK_INVENTORY_SOURCE_CHANGED}: Codex config changed after pre-activation inventory at "
                f"{path}. Retry install after configuration writes have stopped."
            )
    for path, expected in hook_payloads.items():
        if strict_json_object(path, label="Codex hooks file") != expected:
            raise RuntimeError(
                f"{CODEX_HOOK_INVENTORY_SOURCE_CHANGED}: Codex hooks changed after pre-activation inventory at "
                f"{path}. Retry install after configuration writes have stopped."
            )
