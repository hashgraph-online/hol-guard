"""Validate and load Guard extension contribution files."""

from __future__ import annotations

import json
from collections.abc import Mapping
from importlib import import_module
from pathlib import Path
from typing import Final

_SCHEMA_VERSION: Final = "guard.extension-contribution.v1"
_ALLOWED_ICON_NAMES: Final = frozenset(
    {
        "HiMiniBolt",
        "HiMiniCommandLine",
        "HiMiniCube",
        "HiMiniFolder",
        "HiMiniGlobeAlt",
        "HiMiniCloud",
    }
)
_MODULE_PREFIX: Final = "codex_plugin_scanner.guard.runtime."


def contributions_dir() -> Path:
    return Path(__file__).resolve().parents[4] / "contributions" / "extensions"


def load_contribution_payloads(root: Path | None = None) -> tuple[dict[str, object], ...]:
    directory = root if root is not None else contributions_dir()
    if not directory.is_dir():
        return ()
    payloads: list[dict[str, object]] = []
    for path in sorted(directory.glob("command.*.json")):
        payloads.append(validate_contribution_file(path))
    return tuple(payloads)


def validate_contribution_file(path: Path) -> dict[str, object]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"{path.name} must contain an object")
    validate_contribution(payload, filename=path.name)
    return payload


def validate_contribution(payload: Mapping[str, object], *, filename: str = "contribution") -> None:
    if payload.get("schemaVersion") != _SCHEMA_VERSION:
        raise ValueError(f"{filename} has invalid schemaVersion")
    if payload.get("trustClass") != "external":
        raise ValueError(f"{filename} cannot self-declare a non-external trust class")
    if payload.get("activation") != "opt-in":
        raise ValueError(f"{filename} must use opt-in activation")
    extension_id = payload.get("id")
    if not isinstance(extension_id, str) or not extension_id.startswith("command."):
        raise ValueError(f"{filename} has invalid id")
    icon = payload.get("icon")
    if not isinstance(icon, dict):
        raise ValueError(f"{filename} has invalid icon")
    kind = icon.get("kind")
    if kind == "react-icon":
        name = icon.get("name")
        if name not in _ALLOWED_ICON_NAMES:
            raise ValueError(f"{filename} uses an icon name that is not allowlisted")
    detector = payload.get("detector")
    if not isinstance(detector, dict) or detector.get("kind") != "python-module":
        raise ValueError(f"{filename} detector must be an in-tree python-module")
    module_name = detector.get("module")
    if not isinstance(module_name, str) or not module_name.startswith(_MODULE_PREFIX):
        raise ValueError(f"{filename} detector module is outside the runtime package")
    import_module(module_name)


def contribution_ids(root: Path | None = None) -> frozenset[str]:
    ids: set[str] = set()
    for payload in load_contribution_payloads(root):
        extension_id = payload.get("id")
        if isinstance(extension_id, str):
            ids.add(extension_id)
    return frozenset(ids)
