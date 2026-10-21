"""Helpers for launching Guard from managed harness surfaces."""

from __future__ import annotations

import os
import sys
from collections.abc import Mapping
from pathlib import Path

# Native-authority bindings the managed proxy child must inherit from the
# installer process. Persisted into the launcher ``env`` block so the proxy
# keeps the same compiled runtime outside the dev shell; server-supplied env
# must never override them.
_LAUNCHER_BINDING_ENV_VARS: tuple[str, ...] = (
    "HOL_GUARD_NATIVE",
    "HOL_GUARD_NATIVE_BINARY",
    "HOL_GUARD_NATIVE_DIAGNOSTIC",
    "HOL_GUARD_TEST_MODE",
)


def merge_guard_launcher_env(env: Mapping[str, str] | None = None, *, pin_package: bool = False) -> dict[str, str]:
    """Preserve launcher import context while optionally pinning the current package."""

    merged: dict[str, str] = {}
    if pin_package and getattr(sys, "frozen", False):
        # A frozen build imports from its own archive; its package root is a
        # per-process extraction directory that disappears after this run.
        pythonpath = ""
    elif pin_package:
        pythonpath = str(Path(__file__).resolve().parents[2])
    else:
        pythonpath = _normalize_launcher_pythonpath(os.environ.get("PYTHONPATH"))
    if pythonpath:
        merged["PYTHONPATH"] = pythonpath
    for key, value in (env or {}).items():
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
        if key in _LAUNCHER_BINDING_ENV_VARS:
            continue
        merged[key] = value
    for key in _LAUNCHER_BINDING_ENV_VARS:
        value = os.environ.get(key)
        if isinstance(value, str) and value:
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
