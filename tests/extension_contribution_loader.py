"""Load command contribution payloads for tests.

Guard reads command metadata from its compiled native program; nothing in the
runtime loads contribution payloads. Tests still walk the authored, packaged
and installed-bundle copies to check them against each other.
"""

from __future__ import annotations

import json
from importlib import resources
from pathlib import Path
from typing import cast

from codex_plugin_scanner.guard.runtime.extension_contribution import (
    _frozen_runtime,
    frozen_package_data,
    validate_contribution,
)


def load_contribution_payloads(root: Path | None = None) -> tuple[dict[str, object], ...]:
    if root is not None:
        return _load_from_directory(root)
    from tests.installed_compatibility_support import compatibility_payloads

    bundled = compatibility_payloads("commands")
    if bundled is not None:
        return bundled
    packaged = _load_packaged_payloads()
    if packaged:
        return packaged
    return _load_from_directory(Path(__file__).resolve().parents[1] / "contributions" / "extensions")


def validate_contribution_file(path: Path) -> dict[str, object]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"{path.name} must contain an object")
    validate_contribution(payload, filename=path.name)
    return payload


def contribution_ids(root: Path | None = None) -> frozenset[str]:
    ids: set[str] = set()
    for payload in load_contribution_payloads(root):
        extension_id = payload.get("id")
        if isinstance(extension_id, str):
            ids.add(extension_id)
    return frozenset(ids)


def _validated_payload(payload: object, filename: str) -> dict[str, object]:
    if not isinstance(payload, dict):
        raise ValueError(f"{filename} must contain an object")
    validate_contribution(payload, filename=filename)
    return cast(dict[str, object], payload)


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
            if _frozen_runtime():
                raise FileNotFoundError("frozen Guard is missing packaged extension contributions") from None
            return ()
        names = [item for item in frozen.iterdir() if item.name.startswith("command.") and item.name.endswith(".json")]
    if not names:
        if _frozen_runtime():
            raise FileNotFoundError("frozen Guard is missing packaged extension contributions")
        return ()
    payloads: list[dict[str, object]] = []
    for item in sorted(names, key=lambda entry: entry.name):
        payloads.append(_validated_payload(json.loads(item.read_text(encoding="utf-8")), item.name))
    return tuple(payloads)


def contributions_dir() -> Path:
    return Path(__file__).resolve().parents[1] / "contributions" / "extensions"
