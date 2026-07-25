"""Helpers for launching Guard from managed harness surfaces."""

from __future__ import annotations

import os
from collections.abc import Mapping
from pathlib import Path


def merge_guard_launcher_env(env: Mapping[str, str] | None = None, *, pin_package: bool = False) -> dict[str, str]:
    """Preserve launcher import context while optionally pinning the current package."""

    merged: dict[str, str] = {}
    pythonpath = (
        str(Path(__file__).resolve().parents[2])
        if pin_package
        else _normalize_launcher_pythonpath(os.environ.get("PYTHONPATH"))
    )
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
    try:
        relative_base = Path.cwd()
    except OSError:
        return _absolute_path_entries(value or "")
    return _merge_path_entries("", value or "", relative_base=relative_base)


def _absolute_path_entries(value: str) -> str:
    entries: list[str] = []
    for entry in value.split(os.pathsep):
        path = Path(entry.strip()).expanduser()
        if path.is_absolute():
            normalized = str(path)
            if normalized not in entries:
                entries.append(normalized)
    return os.pathsep.join(entries)


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
