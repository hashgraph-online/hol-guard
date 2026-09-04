"""Validate and load Guard extension contribution files."""

from __future__ import annotations

import json
import sys
from collections.abc import Mapping
from functools import lru_cache
from importlib import resources
from pathlib import Path
from typing import Final, cast

from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError

_SCHEMA_VERSION: Final = "guard.extension-contribution.v1"
_PACKAGE_DATA: Final = ("codex_plugin_scanner", "guard", "contracts", "data")


def frozen_package_data(*parts: str) -> Path | None:
    """Return a packaged contract path extracted into a frozen runtime."""

    meipass = getattr(sys, "_MEIPASS", None)
    if not bool(getattr(sys, "frozen", False)) or not isinstance(meipass, str):
        return None
    path = Path(meipass).joinpath(*_PACKAGE_DATA, *parts)
    return path if path.is_file() or path.is_dir() else None


_MODULE_PREFIX: Final = "codex_plugin_scanner.guard.runtime."
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


def contributions_dir() -> Path:
    return Path(__file__).resolve().parents[4] / "contributions" / "extensions"


def load_contribution_payloads(root: Path | None = None) -> tuple[dict[str, object], ...]:
    if root is not None:
        return _load_from_directory(root)
    packaged = _load_packaged_payloads()
    if packaged:
        return packaged
    return _load_from_directory(contributions_dir())


def validate_contribution_file(path: Path) -> dict[str, object]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"{path.name} must contain an object")
    validate_contribution(payload, filename=path.name)
    return payload


def validate_contribution(payload: Mapping[str, object], *, filename: str = "contribution") -> None:
    try:
        _validator().validate(dict(payload))
    except ValidationError as exc:
        raise ValueError(f"{filename} failed contribution schema: {exc.message}") from exc
    if payload.get("trustClass") != "external":
        raise ValueError(f"{filename} cannot self-declare a non-external trust class")
    if payload.get("activation") != "opt-in":
        raise ValueError(f"{filename} must use opt-in activation")
    extension_id = payload.get("id")
    if not isinstance(extension_id, str) or not extension_id.startswith("command."):
        raise ValueError(f"{filename} has invalid id")
    icon = payload.get("icon")
    if isinstance(icon, dict) and icon.get("kind") == "react-icon" and icon.get("name") not in _ALLOWED_ICON_NAMES:
        raise ValueError(f"{filename} uses an icon name that is not allowlisted")
    detector = payload.get("detector")
    if not isinstance(detector, dict):
        raise ValueError(f"{filename} detector must be an in-tree python-module")
    module_name = detector.get("module")
    if not isinstance(module_name, str) or not module_name.startswith(_MODULE_PREFIX):
        raise ValueError(f"{filename} detector module is outside the runtime package")
    _bind_detector(extension_id, module_name, filename)


def contribution_ids(root: Path | None = None) -> frozenset[str]:
    ids: set[str] = set()
    for payload in load_contribution_payloads(root):
        extension_id = payload.get("id")
        if isinstance(extension_id, str):
            ids.add(extension_id)
    return frozenset(ids)


def contribution_catalog_overlay(extension_id: str) -> dict[str, object] | None:
    payload = _contribution_index().get(extension_id)
    if payload is None:
        return None
    publisher = payload.get("publisher")
    icon = payload.get("icon")
    if not isinstance(publisher, dict) or not isinstance(icon, dict):
        return None
    return {"publisher": dict(publisher), "icon": dict(icon)}


def reset_contribution_cache() -> None:
    _contribution_index.cache_clear()
    _validator.cache_clear()


def _load_from_directory(directory: Path) -> tuple[dict[str, object], ...]:
    if not directory.is_dir():
        return ()
    return tuple(validate_contribution_file(path) for path in sorted(directory.glob("command.*.json")))


def _load_packaged_payloads() -> tuple[dict[str, object], ...]:
    try:
        root = resources.files("codex_plugin_scanner.guard.contracts.data.extensions") / "contributions"
        names = [item for item in root.iterdir() if item.name.startswith("command.") and item.name.endswith(".json")]
    except (FileNotFoundError, ModuleNotFoundError, OSError, AttributeError):
        frozen = frozen_package_data("extensions", "contributions")
        if frozen is None or not frozen.is_dir():
            return ()
        names = [item for item in frozen.iterdir() if item.name.startswith("command.") and item.name.endswith(".json")]
    if not names:
        return ()
    payloads: list[dict[str, object]] = []
    for item in sorted(names, key=lambda entry: entry.name):
        payload = json.loads(item.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise ValueError(f"{item.name} must contain an object")
        validate_contribution(payload, filename=item.name)
        payloads.append(payload)
    return tuple(payloads)


@lru_cache(maxsize=1)
def _contribution_index() -> dict[str, dict[str, object]]:
    index: dict[str, dict[str, object]] = {}
    for payload in load_contribution_payloads():
        extension_id = payload.get("id")
        if isinstance(extension_id, str):
            index[extension_id] = payload
    return index


@lru_cache(maxsize=1)
def _validator() -> Draft202012Validator:
    schema = json.loads(_schema_bytes().decode("utf-8"))
    if not isinstance(schema, dict):
        raise ValueError("invalid contribution schema")
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(cast(dict[str, object], schema))


def _schema_bytes() -> bytes:
    try:
        root = resources.files("codex_plugin_scanner.guard.contracts.data.extensions")
        return (root / "contribution.v1.schema.json").read_bytes()
    except (FileNotFoundError, ModuleNotFoundError, OSError):
        frozen = frozen_package_data("extensions", "contribution.v1.schema.json")
        if frozen is not None and frozen.is_file():
            return frozen.read_bytes()
        if bool(getattr(sys, "frozen", False)):
            raise FileNotFoundError("frozen Guard is missing packaged extension contribution schema") from None
        repo_schema = Path(__file__).resolve().parents[4] / "contracts" / "extensions" / "contribution.v1.schema.json"
        return repo_schema.read_bytes()


def _expected_detector_module(extension_id: str) -> str:
    suffix = extension_id.removeprefix("command.").replace("-", "_").replace(".", "_")
    return f"{_MODULE_PREFIX}command_{suffix}_extensions"


def _bind_detector(extension_id: str, module_name: str, filename: str) -> None:
    if module_name != _expected_detector_module(extension_id):
        raise ValueError(f"{filename} detector is not bound to {extension_id}")
    module_leaf = module_name.rsplit(".", 1)[-1]
    path = Path(__file__).with_name(f"{module_leaf}.py")
    if not path.is_file():
        raise ValueError(f"{filename} detector module is missing")
    if f'"{extension_id}"' not in path.read_text(encoding="utf-8"):
        raise ValueError(f"{filename} detector does not define {extension_id}")
