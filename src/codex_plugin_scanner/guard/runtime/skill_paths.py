"""Canonical resolution for installed harness skill documents."""

from __future__ import annotations

import os
from pathlib import Path

from .false_positive_rules import KNOWN_SKILL_DOC_ROOT_SUFFIXES

_UNSAFE_SKILL_URI_MARKERS = ("$", "`", "<", ">", "|", ";", "&")
PI_INLINE_RESOURCE_SCHEMES = frozenset(
    {
        "agent",
        "artifact",
        "history",
        "issue",
        "local",
        "mcp",
        "memory",
        "omp",
        "pr",
        "rule",
        "ssh",
        "vault",
        "xd",
    }
)


def resolve_known_skill_doc_path(target: str, *, home_dir: Path | None = None) -> Path | None:
    """Resolve a valid ``skill://`` URI to its installed ``SKILL.md``."""
    if any(marker in target for marker in _UNSAFE_SKILL_URI_MARKERS):
        return None
    if not target.startswith("skill://"):
        return None
    skill_name = target[len("skill://") :].strip().strip("'\"")
    if not skill_name:
        return None
    skill_name = os.path.normpath(skill_name).replace("\\", "/")
    if skill_name.startswith("..") or skill_name == "." or skill_name.startswith("/"):
        return None

    home = Path(home_dir or Path.home())
    for suffix in KNOWN_SKILL_DOC_ROOT_SUFFIXES:
        candidate_dir = home / suffix / skill_name
        candidate_file = candidate_dir / "SKILL.md"
        if not candidate_file.is_file():
            continue
        # Harnesses commonly symlink a skill directory to a managed source.
        # The document itself must remain within that resolved directory.
        real_candidate = candidate_dir.resolve()
        real_file = candidate_file.resolve()
        if real_file == real_candidate or real_candidate in real_file.parents:
            return real_file
    return None


__all__ = [
    "PI_INLINE_RESOURCE_SCHEMES",
    "resolve_known_skill_doc_path",
]
