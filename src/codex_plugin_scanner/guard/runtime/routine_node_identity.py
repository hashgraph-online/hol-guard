"""Bounded identities for reusable local Node routine approvals."""

from __future__ import annotations

import hashlib
import json
import os
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import cast

_DEPENDENCY_SECTIONS = ("dependencies", "optionalDependencies", "peerDependencies")
_MAX_CLOSURE_PACKAGES = 1_000
_MAX_CLOSURE_BYTES = 512 * 1024 * 1024
_MAX_CLOSURE_FILES = 50_000
_MAX_CONFIG_FILES = 128
_MAX_CONFIG_BYTES = 4 * 1024 * 1024
_STATIC_MODULE_PATTERN = re.compile(r"(?:\bfrom\s+|\brequire\s*\(\s*|\bimport\s*(?:\(\s*)?)['\"](?P<path>[^'\"]+)['\"]")
_COMPUTED_MODULE_PATTERN = re.compile(r"\b(?:require|import)\s*\(\s*(?!['\"])")
_COMMENTED_LOADER_PATTERN = re.compile(
    r"\b(?:createRequire|require|import)\s*(?:/\*.*?\*/|//[^\n]*(?:\n|$))", re.DOTALL
)
_MODULE_SUFFIXES = ("", ".js", ".cjs", ".mjs", ".ts", ".cts", ".mts", ".json")
_NODE_BUILTINS = frozenset(
    {
        "assert",
        "buffer",
        "child_process",
        "cluster",
        "console",
        "crypto",
        "dns",
        "events",
        "fs",
        "http",
        "https",
        "module",
        "net",
        "os",
        "path",
        "perf_hooks",
        "process",
        "querystring",
        "readline",
        "stream",
        "string_decoder",
        "timers",
        "tls",
        "tty",
        "url",
        "util",
        "v8",
        "vm",
        "worker_threads",
        "zlib",
    }
)


@dataclass(slots=True)
class _TreeBudget:
    files: int = 0
    size: int = 0


def routine_workspace_identity(workspace: Path) -> dict[str, object]:
    """Return a stable identity for the canonical workspace directory."""

    canonical = workspace.resolve(strict=True)
    metadata = canonical.stat(follow_symlinks=False)
    return {
        "canonical_path": str(canonical),
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
    }


def routine_dependency_closure_digest(workspace: Path, package_names: tuple[str, ...]) -> str:
    """Hash every installed package reachable from the routine runner."""

    node_modules = (workspace / "node_modules").resolve(strict=True)
    pending = list(package_names)
    budget = _TreeBudget()
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
        records.append((name, version, routine_package_tree_digest(canonical, skip_nested_bin=True, budget=budget)))
        for dependency in _dependency_names(package):
            if (node_modules / dependency).is_dir():
                pending.append(dependency)

    records.sort()
    encoded = json.dumps(records, separators=(",", ":"), ensure_ascii=True).encode()
    return hashlib.sha256(b"hol-guard:node-closure:v1\0" + len(encoded).to_bytes(8, "big") + encoded).hexdigest()


def routine_configuration_identity(workspace: Path, runner: str) -> tuple[str, tuple[str, ...]]:
    """Hash runner configuration and statically referenced local modules."""

    roots = _configuration_roots(workspace, runner)
    pending = list(roots)
    captured: dict[str, str] = {}
    packages: set[str] = set()
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
        suffix = canonical.suffix.lower()
        if suffix in {".yaml", ".yml"} or canonical.name == ".eslintrc":
            raise ValueError("configuration format cannot provide a complete static closure")
        if suffix == ".json":
            local, external = _json_configuration_modules(canonical_workspace, canonical, data)
        else:
            local, external = _script_configuration_modules(canonical_workspace, canonical, data.decode("utf-8"))
        pending.extend(local)
        packages.update(external)
    encoded = json.dumps(sorted(captured.items()), separators=(",", ":"), ensure_ascii=True).encode()
    digest = hashlib.sha256(b"hol-guard:node-config:v1\0" + len(encoded).to_bytes(8, "big") + encoded).hexdigest()
    return digest, tuple(sorted(packages))


def _configuration_roots(workspace: Path, runner: str) -> tuple[Path, ...]:
    names = {
        "next": (
            "next.config.js",
            "next.config.cjs",
            "next.config.mjs",
            "next.config.ts",
            "next.config.cts",
            "next.config.mts",
        ),
        "eslint": (
            "eslint.config.js",
            "eslint.config.cjs",
            "eslint.config.mjs",
            "eslint.config.ts",
            "eslint.config.cts",
            "eslint.config.mts",
            ".eslintrc",
            ".eslintrc.js",
            ".eslintrc.cjs",
            ".eslintrc.json",
            ".eslintrc.yaml",
            ".eslintrc.yml",
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


def _script_configuration_modules(
    workspace: Path, importer: Path, text: str
) -> tuple[tuple[Path, ...], tuple[str, ...]]:
    if (
        _COMPUTED_MODULE_PATTERN.search(text)
        or re.search(r"\bcreateRequire\s*\(", text)
        or _COMMENTED_LOADER_PATTERN.search(text)
    ):
        raise ValueError("configuration contains computed module loading")
    resolved: list[Path] = []
    packages: set[str] = set()
    for match in _STATIC_MODULE_PATTERN.finditer(text):
        raw = match.group("path")
        if not raw.startswith("."):
            package = _bare_package_name(raw)
            if package is not None:
                packages.add(package)
            continue
        resolved.append(_resolve_local_module(workspace, importer, raw))
    return tuple(resolved), tuple(sorted(packages))


def _json_configuration_modules(
    workspace: Path, importer: Path, data: bytes
) -> tuple[tuple[Path, ...], tuple[str, ...]]:
    payload = cast(object, json.loads(data))
    specifiers: list[str] = []
    packages: set[str] = set()
    _collect_json_config_inputs(payload, specifiers, packages)
    resolved: list[Path] = []
    for raw in specifiers:
        if raw.startswith("."):
            resolved.append(_resolve_local_module(workspace, importer, raw))
        else:
            package = _bare_package_name(raw)
            if package is not None:
                packages.add(package)
    return tuple(resolved), tuple(sorted(packages))


def _collect_json_config_inputs(payload: object, specifiers: list[str], packages: set[str]) -> None:
    if isinstance(payload, dict):
        for raw_key, value in cast(dict[object, object], payload).items():
            if not isinstance(raw_key, str):
                continue
            if raw_key in {"extends", "path"}:
                for item in _string_values(value):
                    normalized = _eslint_extended_package(item)
                    (packages.add(normalized) if normalized is not None else specifiers.append(item))
                continue
            if raw_key == "parser" and isinstance(value, str):
                package = _bare_package_name(value)
                if package is not None:
                    packages.add(package)
                continue
            if raw_key == "plugins":
                _collect_plugin_packages(value, packages)
                continue
            _collect_json_config_inputs(value, specifiers, packages)
    elif isinstance(payload, list):
        for value in cast(list[object], payload):
            _collect_json_config_inputs(value, specifiers, packages)


def _string_values(value: object) -> tuple[str, ...]:
    if isinstance(value, str):
        return (value,)
    if isinstance(value, list):
        return tuple(item for item in cast(list[object], value) if isinstance(item, str))
    return ()


def _collect_plugin_packages(value: object, packages: set[str]) -> None:
    if not isinstance(value, list):
        return
    for item in cast(list[object], value):
        if isinstance(item, str):
            packages.add(_eslint_plugin_package(item))
        elif isinstance(item, dict):
            name = cast(dict[object, object], item).get("name")
            if isinstance(name, str):
                package = _bare_package_name(name)
                if package is not None:
                    packages.add(package)


def _eslint_extended_package(specifier: str) -> str | None:
    if not specifier.startswith("plugin:"):
        return None
    remainder = specifier.removeprefix("plugin:")
    parts = remainder.split("/")
    plugin = "/".join(parts[:2]) if remainder.startswith("@") and len(parts) >= 2 else parts[0]
    return _eslint_plugin_package(plugin)


def _eslint_plugin_package(plugin: str) -> str:
    if plugin.startswith("@"):
        scope, _, name = plugin.partition("/")
        if not name:
            return f"{scope}/eslint-plugin"
        return f"{scope}/{name}" if name.startswith("eslint-plugin") else f"{scope}/eslint-plugin-{name}"
    return plugin if plugin.startswith("eslint-plugin-") else f"eslint-plugin-{plugin}"


def _resolve_local_module(workspace: Path, importer: Path, raw: str) -> Path:
    base = importer.parent / raw
    candidates = [
        *(Path(f"{base}{suffix}") for suffix in _MODULE_SUFFIXES),
        *(base / f"index{suffix}" for suffix in _MODULE_SUFFIXES[1:]),
    ]
    target = next((candidate for candidate in candidates if candidate.is_file()), None)
    if target is None:
        raise ValueError("configuration local module is unresolved")
    return _canonical_workspace_file(workspace, target)


def _bare_package_name(specifier: str) -> str | None:
    if specifier.startswith(("node:", "eslint:", "plugin:")) or specifier in _NODE_BUILTINS:
        return None
    parts = specifier.split("/")
    return "/".join(parts[:2]) if specifier.startswith("@") and len(parts) >= 2 else parts[0]


def routine_package_tree_digest(
    root: Path,
    *,
    skip_nested_bin: bool = False,
    budget: _TreeBudget | None = None,
) -> str:
    """Hash an installed package tree with bounded, canonical traversal."""

    canonical_root = root.resolve(strict=True)
    if root.is_symlink() or not canonical_root.is_dir():
        raise ValueError("package tree is not canonical")
    records: list[tuple[str, str]] = []
    active_budget = budget or _TreeBudget()
    for directory, directory_names, file_names in os.walk(canonical_root, followlinks=False):
        directory_names.sort()
        file_names.sort()
        if skip_nested_bin and Path(directory).name == "node_modules" and ".bin" in directory_names:
            directory_names.remove(".bin")
        if any((Path(directory) / name).is_symlink() for name in directory_names):
            raise ValueError("package tree contains a symlink")
        for name in file_names:
            path = Path(directory) / name
            if path.is_symlink():
                raise ValueError("package tree contains a symlink")
            metadata = path.stat()
            if not path.is_file():
                raise ValueError("package tree contains a non-file")
            active_budget.files += 1
            active_budget.size += metadata.st_size
            if active_budget.files > _MAX_CLOSURE_FILES or active_budget.size > _MAX_CLOSURE_BYTES:
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
    "routine_configuration_identity",
    "routine_dependency_closure_digest",
    "routine_package_tree_digest",
    "routine_workspace_identity",
)
