"""Arrange publication assets the way the installed bundle keeps them."""

from __future__ import annotations

from pathlib import Path


def installed_layout(assets: Path) -> None:
    """Name each release tag directory under ``assets`` for its batch alone."""
    for tag in sorted(assets.iterdir()):
        if tag.name.startswith("extension-data-"):
            tag.rename(assets / tag.name.rsplit("-", 1)[1])
