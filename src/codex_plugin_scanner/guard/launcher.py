"""Helpers for launching Guard from managed harness surfaces."""

from __future__ import annotations

import os
from collections.abc import Mapping
from pathlib import Path


def merge_guard_launcher_env(env: Mapping[str, str] | None = None) -> dict[str, str]:
    """Preserve launcher import context when Guard is invoked from source checkouts."""

    merged: dict[str, str] = {}
    pythonpath = os.environ.get("PYTHONPATH")
    if pythonpath:
        merged["PYTHONPATH"] = _merge_path_entries("", pythonpath)
    if env is None:
        return merged
    for key, value in env.items():
        if key == "PYTHONPATH":
            merged["PYTHONPATH"] = _merge_path_entries(merged.get("PYTHONPATH", ""), value)
            continue
        merged[key] = value
    return merged


def _merge_path_entries(left: str, right: str) -> str:
    values: list[str] = []
    for entry in [*left.split(os.pathsep), *right.split(os.pathsep)]:
        normalized = _normalize_path_entry(entry)
        if normalized and normalized not in values:
            values.append(normalized)
    return os.pathsep.join(values)


def _normalize_path_entry(entry: str) -> str:
    trimmed = entry.strip()
    if not trimmed:
        return ""
    path = Path(trimmed).expanduser()
    if path.is_absolute():
        return str(path)
    return str((Path.cwd() / path).resolve())


__all__ = ["merge_guard_launcher_env"]
