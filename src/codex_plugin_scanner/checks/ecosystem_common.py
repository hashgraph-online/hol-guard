"""Shared helpers for non-Codex ecosystem checks."""

from __future__ import annotations

import re

SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+$")


def has_frontmatter(text: str) -> bool:
    """Check if markdown text starts with frontmatter."""

    stripped = text.lstrip()
    if not stripped.startswith("---"):
        return False
    parts = stripped.split("---", 2)
    if len(parts) < 3:
        return False
    frontmatter = parts[1]
    return "name:" in frontmatter and "description:" in frontmatter
