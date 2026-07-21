"""Bounded, hash-bound inputs for contained explicit-source TypeScript checks."""

from __future__ import annotations

import hashlib
import json
import os
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Final

from .containment_contract import ContainmentInput
from .containment_executor import file_sha256

_MAX_TREE_FILES: Final = 10_000
_MAX_TREE_BYTES: Final = 128 * 1024 * 1024
_MAX_SOURCE_BYTES: Final = 32 * 1024 * 1024
_MAX_DISCOVERY_ENTRIES: Final = 50_000
_DISCOVERY_TIMEOUT_SECONDS: Final = 5.0
_PROTECTED_NAMES: Final = frozenset(
    {".git", ".ssh", ".aws", ".gnupg", ".guard", "credentials", "credentials.json", "secrets.json"}
)
_TYPESCRIPT_INPUT_SUFFIXES: Final = frozenset({".cjs", ".cts", ".js", ".jsx", ".mjs", ".mts", ".ts", ".tsx"})


def typescript_snapshot_inputs(
    workspace: Path,
    package_root: Path,
    sources: tuple[str, ...],
) -> tuple[str, tuple[ContainmentInput, ...], str, tuple[ContainmentInput, ...]]:
    """Return exact compiler and workspace closures or reject uncertain discovery."""

    tree_digest, package_inputs = _tree_inputs(workspace, package_root)
    closure_digest, closure_inputs = _typescript_closure_inputs(workspace, package_root, sources)
    return tree_digest, package_inputs, closure_digest, closure_inputs


def _tree_inputs(workspace: Path, root: Path) -> tuple[str, tuple[ContainmentInput, ...]]:
    canonical_root = _canonical_directory(root)
    captured: list[tuple[str, str, ContainmentInput]] = []
    total_bytes = 0
    started_at = time.monotonic()
    visited_entries = [0]
    directories = [canonical_root]
    while directories:
        directory = directories.pop()
        for entry in _bounded_entries(directory, started_at, visited_entries):
            path = Path(entry.path)
            relative = path.relative_to(canonical_root)
            if _is_protected_path(relative):
                raise ValueError("protected package-tree path")
            if entry.is_symlink():
                raise ValueError("package tree cannot contain symlinks")
            if entry.is_dir(follow_symlinks=False):
                directories.append(path)
                continue
            if not entry.is_file(follow_symlinks=False):
                raise ValueError("package tree inputs must be regular files")
            total_bytes += entry.stat(follow_symlinks=False).st_size
            if len(captured) >= _MAX_TREE_FILES or total_bytes > _MAX_TREE_BYTES:
                raise ValueError("package tree exceeds containment identity budget")
            digest = _file_digest(path)
            _check_discovery_budget(started_at, visited_entries[0])
            snapshot_path = path.relative_to(workspace).as_posix()
            captured.append(
                (
                    relative.as_posix(),
                    digest,
                    ContainmentInput(str(path), snapshot_path, digest),
                )
            )
    if not captured:
        raise ValueError("package tree is empty")
    captured.sort(key=lambda item: item[0])
    records = [(relative, digest) for relative, digest, _item in captured]
    return _binding_digest({"files": records}), tuple(item for _relative, _digest, item in captured)


def _typescript_closure_inputs(
    workspace: Path,
    package_root: Path,
    sources: tuple[str, ...],
) -> tuple[str, tuple[ContainmentInput, ...]]:
    _reject_external_node_modules(workspace)
    source_paths = _validated_source_paths(workspace, sources)
    captured: list[tuple[str, str, ContainmentInput]] = []
    total_bytes = 0
    started_at = time.monotonic()
    visited_entries = [0]
    directories = [workspace]
    while directories:
        directory = directories.pop()
        for entry in _bounded_entries(directory, started_at, visited_entries):
            path = Path(entry.path)
            relative = path.relative_to(workspace)
            if path == package_root or (entry.is_dir(follow_symlinks=False) and entry.name == ".bin"):
                continue
            if _is_protected_path(relative):
                if _protected_path_requires_review(relative):
                    raise ValueError("protected TypeScript dependency cannot be omitted")
                continue
            if entry.is_symlink():
                raise ValueError("TypeScript closure cannot contain symlinks")
            if entry.is_dir(follow_symlinks=False):
                directories.append(path)
                continue
            if not entry.is_file(follow_symlinks=False):
                raise ValueError("TypeScript closure inputs must be regular files")
            if not _is_typescript_input(relative):
                continue
            canonical = path.resolve(strict=True)
            total_bytes += entry.stat(follow_symlinks=False).st_size
            if len(captured) >= _MAX_TREE_FILES or total_bytes > _MAX_SOURCE_BYTES:
                raise ValueError("TypeScript closure exceeds containment identity budget")
            digest = _file_digest(canonical)
            _check_discovery_budget(started_at, visited_entries[0])
            snapshot_path = relative.as_posix()
            captured.append(
                (
                    snapshot_path,
                    digest,
                    ContainmentInput(str(canonical), snapshot_path, digest),
                )
            )
    captured.sort(key=lambda item: item[0])
    captured_paths = {path for path, _digest, _item in captured}
    if not all(path.relative_to(workspace).as_posix() in captured_paths for path in source_paths):
        raise ValueError("TypeScript closure omitted an explicit source")
    records = [(path, digest) for path, digest, _item in captured]
    return _binding_digest({"files": records}), tuple(item for _path, _digest, item in captured)


def _bounded_entries(
    directory: Path,
    started_at: float,
    visited_entries: list[int],
) -> Iterator[os.DirEntry[str]]:
    try:
        with os.scandir(directory) as entries:
            for entry in entries:
                visited_entries[0] += 1
                _check_discovery_budget(started_at, visited_entries[0])
                yield entry
    except OSError as exc:
        raise ValueError("containment input discovery failed") from exc


def _validated_source_paths(workspace: Path, sources: tuple[str, ...]) -> tuple[Path, ...]:
    canonical_sources: list[Path] = []
    for raw_source in sources:
        candidate = workspace / raw_source
        if candidate.is_symlink() or not candidate.is_file():
            raise ValueError("source must be a regular non-symlinked file")
        canonical = candidate.resolve(strict=True)
        try:
            relative = canonical.relative_to(workspace)
        except ValueError as exc:
            raise ValueError("source escaped workspace") from exc
        if _is_protected_path(relative) or ".bin" in relative.parts:
            raise ValueError("protected source path")
        canonical_sources.append(canonical)
    if len(canonical_sources) != len(set(canonical_sources)):
        raise ValueError("source closure cannot contain aliases")
    return tuple(canonical_sources)


def _reject_external_node_modules(workspace: Path) -> None:
    for ancestor in workspace.parents:
        dependency_root = ancestor / "node_modules"
        try:
            _ = dependency_root.lstat()
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise ValueError("external TypeScript dependency identity is unavailable") from exc
        raise ValueError("external TypeScript dependencies require Guard review")


def _is_protected_path(relative: Path) -> bool:
    return any(part.lower() in _PROTECTED_NAMES or part.lower().startswith(".env") for part in relative.parts)


def _protected_path_requires_review(relative: Path) -> bool:
    lowered_parts = tuple(part.lower() for part in relative.parts)
    return "node_modules" in lowered_parts or _is_typescript_input(relative)


def _is_typescript_input(relative: Path) -> bool:
    return relative.name == "package.json" or relative.suffix.lower() in _TYPESCRIPT_INPUT_SUFFIXES


def _check_discovery_budget(started_at: float, visited_entries: int) -> None:
    if visited_entries > _MAX_DISCOVERY_ENTRIES:
        raise ValueError("containment discovery entry budget exceeded")
    if time.monotonic() - started_at > _DISCOVERY_TIMEOUT_SECONDS:
        raise ValueError("containment discovery time budget exceeded")


def _canonical_directory(path: Path) -> Path:
    if path.is_symlink() or not path.is_dir():
        raise ValueError("package tree must be an existing canonical directory")
    canonical = path.resolve(strict=True)
    if canonical != Path(os.path.normpath(str(path))):
        raise ValueError("package tree cannot contain aliases")
    return canonical


def _file_digest(path: Path) -> str:
    return file_sha256(str(path))


def _binding_digest(payload: dict[str, object]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    return hashlib.sha256(len(encoded).to_bytes(8, "big") + encoded).hexdigest()


__all__ = ("typescript_snapshot_inputs",)
