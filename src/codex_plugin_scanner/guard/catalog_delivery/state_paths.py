"""Guard-home state paths whose operating-system prefix is resolved once."""

from __future__ import annotations

import os
from pathlib import Path


def resolved_guard_home(guard_home: Path) -> Path:
    """Return the Guard home with the prefix above it resolved exactly once.

    ``checked_path`` rejects a symlink in every existing component. That is the
    right rule for everything this program creates and the wrong rule for the
    directories above the Guard home, which the operating system or the
    administrator chose: Fedora Silverblue reaches ``/home`` through a symlink
    to ``var/home``, a relocated home directory does the same, macOS reaches
    the per-user temporary directory through ``/var``, and a Windows profile
    can sit behind a directory symlink. None of those are picked by the code
    that opens a cache file, so refusing to read through them leaves Guard
    unable to read its own state at all.

    Only the prefix above the Guard home is resolved. The Guard home's own
    component and every component below it stay symlink-checked, so a link
    planted inside the tree -- the part an attacker who can write there would
    have to plant, and the only part this program creates -- is still refused.
    A path carrying parent traversal is returned unchanged for ``checked_path``
    to reject.
    """

    home = Path(guard_home).absolute()
    if ".." in home.parts:
        return home
    parent = home.parent
    if parent == home:
        return home
    try:
        return Path(os.path.realpath(parent)) / home.name
    except OSError:
        return home
