"""Bounded identities for reusable local Node routine approvals."""

from __future__ import annotations

import hashlib
import json
import os
import re
from collections.abc import Mapping
from pathlib import Path
from typing import cast

_DEPENDENCY_SECTIONS = ("dependencies", "optionalDependencies", "peerDependencies")
_MAX_CLOSURE_PACKAGES = 1_000
_MAX_PACKAGE_TREE_BYTES = 256 * 1024 * 1024
_MAX_PACKAGE_TREE_FILES = 12_000
_MAX_CONFIG_FILES = 128
_MAX_CONFIG_BYTES = 4 * 1024 * 1024
_LOCAL_MODULE_PATTERN = re.compile(r"(?:from\s+|require\s*\(|import\s*\()\s*['\"](?P<path>\.{1,2}/[^'\"]+)['\"]")
_MODULE_SUFFIXES = ("", ".js", ".cjs", ".mjs", ".ts", ".cts", ".mts", ".json")


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


def routine_configuration_digest(workspace: Path, runner: str) -> str:
    """Hash runner configuration and statically referenced local modules."""

    roots = _configuration_roots(workspace, runner)
    pending = list(roots)
    captured: dict[str, str] = {}
    total_bytes = 0
    canonical_workspace = workspace.resolve(strict=True)
    while pending:
        path = pending.pop()
        canonical = _canonical_workspace_file(canonical_workspace, path)
        relative = canonical.relative_to(canonical_workspace).as_posix()
        if relative in captured:
            continue
        if len(captured) >= _MAX_CONFIG_FILES:
            raise ValueError("configuration closure exceeds identity budget")
        data = canonical.read_bytes()
        total_bytes += len(data)
        if total_bytes > _MAX_CONFIG_BYTES:
            raise ValueError("configuration closure exceeds identity budget")
        captured[relative] = hashlib.sha256(data).hexdigest()
        if canonical.suffix.lower() != ".json":
            text = data.decode("utf-8")
            pending.extend(_resolved_local_modules(canonical_workspace, canonical, text))
    encoded = json.dumps(sorted(captured.items()), separators=(",", ":"), ensure_ascii=True).encode()
    return hashlib.sha256(b"hol-guard:node-config:v1\0" + len(encoded).to_bytes(8, "big") + encoded).hexdigest()


def _configuration_roots(workspace: Path, runner: str) -> tuple[Path, ...]:
    names = {
        "next": ("next.config.js", "next.config.cjs", "next.config.mjs", "next.config.ts", "next.config.mts"),
        "eslint": (
            "eslint.config.js",
            "eslint.config.cjs",
            "eslint.config.mjs",
            "eslint.config.ts",
            ".eslintrc.js",
            ".eslintrc.cjs",
            ".eslintrc.json",
        ),
        "tsc": ("tsconfig.json",),
    }[runner]
    candidates = [workspace / "package.json", *(workspace / name for name in names)]
    return tuple(path for path in candidates if path.exists())


def _canonical_workspace_file(workspace: Path, path: Path) -> Path:
    if path.is_symlink() or not path.is_file():
        raise ValueError("configuration closure contains an unavailable file")
    canonical = path.resolve(strict=True)
    try:
        _ = canonical.relative_to(workspace)
    except ValueError as exc:
        raise ValueError("configuration closure escaped workspace") from exc
    if "node_modules" in canonical.relative_to(workspace).parts:
        raise ValueError("configuration closure entered node_modules")
    return canonical


def _resolved_local_modules(workspace: Path, importer: Path, text: str) -> tuple[Path, ...]:
    resolved: list[Path] = []
    for match in _LOCAL_MODULE_PATTERN.finditer(text):
        raw = match.group("path")
        base = importer.parent / raw
        candidates = [
            *(Path(f"{base}{suffix}") for suffix in _MODULE_SUFFIXES),
            *(base / f"index{suffix}" for suffix in _MODULE_SUFFIXES[1:]),
        ]
        target = next((candidate for candidate in candidates if candidate.is_file()), None)
        if target is None:
            raise ValueError("configuration local module is unresolved")
        resolved.append(_canonical_workspace_file(workspace, target))
    return tuple(resolved)


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


__all__ = (
    "routine_configuration_digest",
    "routine_dependency_closure_digest",
    "routine_package_tree_digest",
    "routine_workspace_identity",
)
