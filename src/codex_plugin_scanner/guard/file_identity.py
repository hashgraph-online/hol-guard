"""Shared filesystem identity tuples used for race detection."""

from __future__ import annotations

import os


def full_stat_identity(metadata: os.stat_result) -> tuple[int, ...]:
    """Return a portable stat identity including link, time, and Windows attributes."""

    return (
        int(metadata.st_dev),
        int(metadata.st_ino),
        int(metadata.st_mode),
        int(metadata.st_nlink),
        int(metadata.st_size),
        int(getattr(metadata, "st_mtime_ns", int(metadata.st_mtime * 1_000_000_000))),
        int(getattr(metadata, "st_ctime_ns", int(metadata.st_ctime * 1_000_000_000))),
        int(getattr(metadata, "st_file_attributes", 0)),
    )


def content_stat_identity(metadata: os.stat_result) -> tuple[int, int, int, int, int, int]:
    """Return the compact stat tuple used to detect content/path replacement."""

    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
        metadata.st_mode,
    )


__all__ = ["content_stat_identity", "full_stat_identity"]
