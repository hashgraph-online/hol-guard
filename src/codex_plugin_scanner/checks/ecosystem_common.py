"""Shared helpers for non-Codex ecosystem checks."""

from __future__ import annotations

import json
import re
from pathlib import Path

SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+$")


def load_json(path: Path) -> dict[str, object] | None:
    """Load a JSON object from disk."""

    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None
    if not isinstance(payload, dict):
        return None
    return payload


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
