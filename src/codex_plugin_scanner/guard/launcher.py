"""Helpers for launching Guard from managed harness surfaces."""

from __future__ import annotations

import os
from collections.abc import Mapping
from pathlib import Path


def merge_guard_launcher_env(env: Mapping[str, str] | None = None) -> dict[str, str]:
    """Preserve launcher import context when Guard is invoked from source checkouts."""

    merged: dict[str, str] = {}
    pythonpath = _normalize_launcher_pythonpath(os.environ.get("PYTHONPATH"))
    if pythonpath:
        merged["PYTHONPATH"] = pythonpath
    if env is None:
        return merged
    for key, value in env.items():
        if key == "PYTHONPATH":
            if value.strip() == "":
                merged["PYTHONPATH"] = ""
                continue
            pythonpath = _merge_path_entries(merged.get("PYTHONPATH", ""), value)
            if pythonpath:
                merged["PYTHONPATH"] = pythonpath
            else:
                merged.pop("PYTHONPATH", None)
            continue
        merged[key] = value
    return merged


def _normalize_launcher_pythonpath(value: str | None) -> str:
    return _merge_path_entries("", value or "", relative_base=Path.cwd())


def _merge_path_entries(left: str, right: str, relative_base: Path | None = None) -> str:
    values: list[str] = []
    for entry in [*left.split(os.pathsep), *right.split(os.pathsep)]:
        normalized = _normalize_path_entry(entry, relative_base=relative_base)
        if normalized and normalized not in values:
            values.append(normalized)
    return os.pathsep.join(values)


def _normalize_path_entry(entry: str, relative_base: Path | None = None) -> str:
    trimmed = entry.strip()
    if not trimmed:
        return ""
    path = Path(trimmed).expanduser()
    if path.is_absolute():
        return str(path)
    if relative_base is None:
        return trimmed
    return str((relative_base / path).resolve())


__all__ = ["merge_guard_launcher_env"]
