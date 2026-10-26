"""Shared source-file identity helpers for Gauntlet evidence."""

from __future__ import annotations

from pathlib import Path

from .fixtures import digest_file


def digest_runner_files(directory: Path) -> dict[str, str]:
    """Return bounded file identities for the Gauntlet implementation directory."""
    return {path.name: digest_file(path) for path in sorted(directory.iterdir()) if path.is_file()}
