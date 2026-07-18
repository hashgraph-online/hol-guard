"""Bounded, race-aware artifact evidence for managed user harnesses."""

from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path
from typing import cast

_MAX_ARTIFACT_BYTES = 2 * 1024 * 1024
_MAX_DIRECTORY_BYTES = 4 * 1024 * 1024
_MAX_DIRECTORY_ENTRIES = 128
_MAX_MANIFEST_DEPTH = 16
_MAX_MANIFEST_NODES = 2048
_PATH_KEYS = frozenset(
    {
        "config_path",
        "extension_path",
        "hook_path",
        "managed_config_path",
        "plugin_path",
        "shim_path",
        "shim_paths",
    }
)


def artifact_digest(path: Path) -> tuple[str, str | None]:
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode):
        return "missing", None
    if stat.S_ISDIR(metadata.st_mode):
        digest = _directory_digest(path)
        try:
            final_directory = path.lstat()
        except OSError:
            return "missing", None
        directory_fields = ("st_dev", "st_ino", "st_mtime_ns", "st_ctime_ns")
        if (
            digest is None
            or not stat.S_ISDIR(final_directory.st_mode)
            or any(getattr(metadata, field) != getattr(final_directory, field) for field in directory_fields)
        ):
            return "missing", None
        return "directory", digest
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > _MAX_ARTIFACT_BYTES:
        return "missing", None
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size > _MAX_ARTIFACT_BYTES:
            return "missing", None
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 64 * 1024))
            if not chunk:
                return "missing", None
            chunks.append(chunk)
            remaining -= len(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    stable_fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
    try:
        final = path.lstat()
    except OSError:
        return "missing", None
    if not stat.S_ISREG(final.st_mode) or any(
        len({getattr(metadata, field), getattr(before, field), getattr(after, field), getattr(final, field)}) != 1
        for field in stable_fields
    ):
        return "missing", None
    return "file", hashlib.sha256(b"".join(chunks)).hexdigest()


def _directory_digest(path: Path) -> str | None:
    entries: list[str] = []
    total_bytes = 0
    for root, directories, files in os.walk(path, followlinks=False, onerror=_raise_walk_error):
        if len(entries) + len(directories) + len(files) > _MAX_DIRECTORY_ENTRIES:
            return None
        directories.sort()
        files.sort()
        root_path = Path(root)
        for name in directories:
            candidate = root_path / name
            try:
                metadata = candidate.lstat()
            except OSError:
                return None
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
                return None
            entries.append(f"d:{candidate.relative_to(path)}")
        for name in files:
            candidate = root_path / name
            try:
                metadata = candidate.lstat()
            except OSError:
                return None
            if not stat.S_ISREG(metadata.st_mode):
                return None
            total_bytes += metadata.st_size
            if total_bytes > _MAX_DIRECTORY_BYTES:
                return None
            kind, digest = artifact_digest(candidate)
            if kind != "file" or digest is None:
                return None
            entries.append(f"f:{candidate.relative_to(path)}:{digest}")
        if len(entries) > _MAX_DIRECTORY_ENTRIES:
            return None
    return hashlib.sha256("\n".join(entries).encode("utf-8")).hexdigest() if entries else None


def _raise_walk_error(error: OSError) -> None:
    raise error


def managed_manifest_paths(manifest: dict[str, object], home: Path, *, limit: int) -> list[Path]:
    candidates: list[str] = []
    stack: list[tuple[object, int]] = [(manifest, 0)]
    visited = 0
    while stack:
        value, depth = stack.pop()
        visited += 1
        if visited > _MAX_MANIFEST_NODES or depth > _MAX_MANIFEST_DEPTH:
            raise ValueError("harness_coverage_manifest_invalid")
        if isinstance(value, dict):
            mapping = cast(dict[object, object], value)
            if len(mapping) > _MAX_MANIFEST_NODES:
                raise ValueError("harness_coverage_manifest_invalid")
            for key, item in mapping.items():
                if isinstance(key, str) and key in _PATH_KEYS:
                    if isinstance(item, str) and item.strip():
                        candidates.append(item)
                    elif isinstance(item, list):
                        candidates.extend(
                            entry for entry in cast(list[object], item) if isinstance(entry, str) and entry.strip()
                        )
                elif isinstance(key, str) and isinstance(item, (dict, list)):
                    stack.append((cast(object, item), depth + 1))
        elif isinstance(value, list):
            items = cast(list[object], value)
            if len(items) > _MAX_MANIFEST_NODES:
                raise ValueError("harness_coverage_manifest_invalid")
            for item in items:
                stack.append((item, depth + 1))
    resolved_home = home.resolve(strict=True)
    resolved: list[Path] = []
    for raw in candidates:
        candidate = Path(raw).expanduser()
        if not candidate.is_absolute():
            candidate = resolved_home / candidate
        try:
            normalized = candidate.resolve(strict=False)
        except OSError:
            continue
        if normalized != resolved_home and normalized.is_relative_to(resolved_home):
            resolved.append(normalized)
    return sorted(set(resolved))[:limit]


__all__ = ["artifact_digest", "managed_manifest_paths"]
