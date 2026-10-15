"""Typed projection of the native no-follow Linux read index."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from ..native_restricted_linux import read_grants

_MAX_ENTRIES = 240_000


@dataclass(frozen=True, slots=True)
class LinuxReadGrant:
    path: Path
    device: int
    inode: int


def collect_linux_read_grants(root: Path, *, max_entries: int = _MAX_ENTRIES) -> tuple[LinuxReadGrant, ...]:
    return tuple(
        LinuxReadGrant(Path(row["path"]), row["device"], row["inode"]) for row in read_grants(root, max_entries)
    )
