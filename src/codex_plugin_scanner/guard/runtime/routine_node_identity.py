"""Bounded identities for reusable local Node routine approvals."""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Mapping
from pathlib import Path
from typing import cast

_DEPENDENCY_SECTIONS = ("dependencies", "optionalDependencies", "peerDependencies")
_MAX_CLOSURE_PACKAGES = 1_000
_MAX_PACKAGE_TREE_BYTES = 256 * 1024 * 1024
_MAX_PACKAGE_TREE_FILES = 12_000


def routine_workspace_identity(workspace: Path) -> dict[str, object]:
    """Return a stable identity for the canonical workspace directory."""

    canonical = workspace.resolve(strict=True)
    metadata = canonical.stat(follow_symlinks=False)
    return {
        "canonical_path": str(canonical),
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
    }


def routine_dependency_closure_digest(workspace: Path, package_name: str) -> str:
    """Hash every installed package reachable from the routine runner."""

    node_modules = (workspace / "node_modules").resolve(strict=True)
    pending = [package_name]
    visited: set[str] = set()
    records: list[tuple[str, str, str]] = []
    while pending:
        name = pending.pop()
        if name in visited:
            continue
        if len(visited) >= _MAX_CLOSURE_PACKAGES:
            raise ValueError("dependency closure exceeds identity budget")
        package_dir = node_modules / name
        if package_dir.is_symlink() or not package_dir.is_dir():
            raise ValueError("dependency closure contains an unavailable package")
        canonical = package_dir.resolve(strict=True)
        try:
            _ = canonical.relative_to(node_modules)
        except ValueError as exc:
            raise ValueError("dependency closure escaped node_modules") from exc
        package = _read_package_json(canonical / "package.json")
        if package is None or package.get("name") != name:
            raise ValueError("dependency closure package identity is invalid")
        version = package.get("version")
        if not isinstance(version, str):
            raise ValueError("dependency closure package version is invalid")
        visited.add(name)
        records.append((name, version, routine_package_tree_digest(canonical, skip_nested_bin=True)))
        for dependency in _dependency_names(package):
            if (node_modules / dependency).is_dir():
                pending.append(dependency)

    records.sort()
    encoded = json.dumps(records, separators=(",", ":"), ensure_ascii=True).encode()
    return hashlib.sha256(b"hol-guard:node-closure:v1\0" + len(encoded).to_bytes(8, "big") + encoded).hexdigest()


def routine_package_tree_digest(root: Path, *, skip_nested_bin: bool = False) -> str:
    """Hash an installed package tree with bounded, canonical traversal."""

    canonical_root = root.resolve(strict=True)
    if root.is_symlink() or not canonical_root.is_dir():
        raise ValueError("package tree is not canonical")
    records: list[tuple[str, str]] = []
    total_bytes = 0
    for directory, directory_names, file_names in os.walk(canonical_root, followlinks=False):
        directory_names.sort()
        file_names.sort()
        if skip_nested_bin and Path(directory).name == "node_modules" and ".bin" in directory_names:
            directory_names.remove(".bin")
        for name in file_names:
            path = Path(directory) / name
            if path.is_symlink():
                raise ValueError("package tree contains a symlink")
            metadata = path.stat()
            if not path.is_file():
                raise ValueError("package tree contains a non-file")
            total_bytes += metadata.st_size
            if len(records) >= _MAX_PACKAGE_TREE_FILES or total_bytes > _MAX_PACKAGE_TREE_BYTES:
                raise ValueError("package tree exceeds identity budget")
            records.append((path.relative_to(canonical_root).as_posix(), hashlib.sha256(path.read_bytes()).hexdigest()))
    encoded = json.dumps(records, separators=(",", ":"), ensure_ascii=True).encode()
    return hashlib.sha256(b"hol-guard:package-tree:v1\0" + len(encoded).to_bytes(8, "big") + encoded).hexdigest()


def _dependency_names(package: dict[str, object]) -> tuple[str, ...]:
    names: set[str] = set()
    for section in _DEPENDENCY_SECTIONS:
        dependencies = package.get(section)
        if not isinstance(dependencies, Mapping):
            continue
        names.update(key for key in cast(Mapping[object, object], dependencies) if isinstance(key, str))
    return tuple(sorted(names))


def _read_package_json(path: Path) -> dict[str, object] | None:
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 16 * 1024 * 1024:
            return None
        payload = cast(object, json.loads(path.read_text(encoding="utf-8")))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict):
        return None
    typed = cast(dict[object, object], payload)
    return {key: value for key, value in typed.items() if isinstance(key, str)}


__all__ = ("routine_dependency_closure_digest", "routine_package_tree_digest", "routine_workspace_identity")
