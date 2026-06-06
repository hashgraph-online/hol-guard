"""Adapter protocol for ecosystem-specific scanners."""

from __future__ import annotations

from fnmatch import fnmatchcase
from pathlib import Path
from typing import Protocol

from ..path_support import resolves_within_root
from .types import Ecosystem, NormalizedPackage, PackageCandidate

IGNORED_ECOSYSTEM_DIRS = frozenset({"node_modules", ".git", ".venv", "venv", "dist", "__pycache__"})


def iter_safe_recursive_files(root: Path, base_dir: Path, pattern: str) -> tuple[Path, ...]:
    """Recursively enumerate in-root non-symlink files matching a glob name."""

    try:
        resolved_root = root.resolve()
    except (OSError, RuntimeError):
        return ()
    if base_dir.is_symlink():
        return ()
    if not base_dir.is_dir() or not resolves_within_root(resolved_root, base_dir, require_exists=True):
        return ()

    matches: list[Path] = []
    pending: list[Path] = [base_dir]
    while pending:
        current_dir = pending.pop()
        try:
            entries = sorted(current_dir.iterdir(), key=lambda path: path.name)
        except OSError:
            continue
        for entry in entries:
            if entry.name in IGNORED_ECOSYSTEM_DIRS:
                try:
                    if entry.is_dir():
                        continue
                except OSError:
                    continue
            if entry.is_symlink():
                continue
            try:
                if entry.is_dir():
                    if resolves_within_root(resolved_root, entry, require_exists=True):
                        pending.append(entry)
                    continue
                if not entry.is_file():
                    continue
            except OSError:
                continue
            if not resolves_within_root(resolved_root, entry, require_exists=True):
                continue
            if fnmatchcase(entry.name, pattern):
                matches.append(entry)
    return tuple(sorted(matches, key=lambda path: str(path)))


def iter_safe_recursive_dirs(root: Path, base_dir: Path, pattern: str) -> tuple[Path, ...]:
    """Recursively enumerate in-root non-symlink directories matching a glob name."""

    try:
        resolved_root = root.resolve()
    except (OSError, RuntimeError):
        return ()
    if base_dir.is_symlink():
        return ()
    if not base_dir.is_dir() or not resolves_within_root(resolved_root, base_dir, require_exists=True):
        return ()

    matches: list[Path] = []
    pending: list[Path] = [base_dir]
    while pending:
        current_dir = pending.pop()
        try:
            entries = sorted(current_dir.iterdir(), key=lambda path: path.name)
        except OSError:
            continue
        for entry in entries:
            if entry.is_symlink():
                continue
            try:
                if not entry.is_dir():
                    continue
            except OSError:
                continue
            if entry.name in IGNORED_ECOSYSTEM_DIRS:
                continue
            if not resolves_within_root(resolved_root, entry, require_exists=True):
                continue
            if fnmatchcase(entry.name, pattern):
                matches.append(entry)
            pending.append(entry)
    return tuple(sorted(matches, key=lambda path: str(path)))


class EcosystemAdapter(Protocol):
    """Contract implemented by ecosystem adapters."""

    ecosystem_id: Ecosystem

    def detect(self, root: Path) -> list[PackageCandidate]:
        """Detect package candidates for this ecosystem."""

    def parse(self, candidate: PackageCandidate) -> NormalizedPackage:
        """Parse a detected package candidate into normalized form."""
