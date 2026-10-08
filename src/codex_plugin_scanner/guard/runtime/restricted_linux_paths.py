"""Bounded, no-follow file grants for Linux repository execution.

The tree index never reads file data. It excludes credential paths and ambiguous
hardlinks, and pins each admitted inode for revalidation by the kernel launcher.
Directory handles, rather than followed path strings, drive recursive discovery.
"""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from pathlib import Path

from .restricted_linux_landlock import LinuxContainmentUnavailableError
from .secret_sensitivity import classify_secret_path

_MAX_ENTRIES = 240_000
_PROTECTED_DIRECTORIES = frozenset({".ssh", ".aws", ".docker", ".kube", ".gnupg", ".hol-guard"})


@dataclass(frozen=True, slots=True)
class LinuxReadGrant:
    path: Path
    device: int
    inode: int


def collect_linux_read_grants(root: Path, *, max_entries: int = _MAX_ENTRIES) -> tuple[LinuxReadGrant, ...]:
    """Index ordinary regular files; never follow links or admit secret aliases.

    Shared hardlinked package files need an independently verified cache binding
    before admission. Link count alone cannot establish the other names' safety.
    A discovery/race error aborts the plan, rather than partially admitting it.
    """
    if not root.is_absolute() or not 0 < max_entries <= _MAX_ENTRIES:
        raise LinuxContainmentUnavailableError("Invalid Linux workspace discovery boundary.")
    grants: list[LinuxReadGrant] = []
    visited = 0

    def protected(path: Path) -> bool:
        return (
            path.name.lower() in _PROTECTED_DIRECTORIES
            or classify_secret_path(str(path), cwd=root, home_dir=root) is not None
        )

    def walk(directory: Path, descriptor: int) -> None:
        nonlocal visited
        with os.scandir(descriptor) as entries:
            for entry in entries:
                visited += 1
                if visited > max_entries:
                    raise LinuxContainmentUnavailableError("Linux workspace discovery exceeds its entry budget.")
                path = directory / entry.name
                metadata = entry.stat(follow_symlinks=False)
                if protected(path) or stat.S_ISLNK(metadata.st_mode):
                    continue
                if stat.S_ISDIR(metadata.st_mode):
                    child = os.open(entry.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
                    try:
                        opened = os.fstat(child)
                        if (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino):
                            raise LinuxContainmentUnavailableError("Linux workspace changed during discovery.")
                        walk(path, child)
                    finally:
                        os.close(child)
                elif stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1:
                    grants.append(LinuxReadGrant(path, metadata.st_dev, metadata.st_ino))

    try:
        if root.resolve(strict=True) != root or any(
            part.lower() in _PROTECTED_DIRECTORIES or part.lower() == ".env" or part.lower().startswith(".env.")
            for part in root.parts
        ):
            raise LinuxContainmentUnavailableError("Linux workspace is not a canonical nonsensitive directory.")
        descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            walk(root, descriptor)
        finally:
            os.close(descriptor)
    except OSError as error:
        raise LinuxContainmentUnavailableError("Linux workspace could not be indexed safely.") from error
    return tuple(grants)
