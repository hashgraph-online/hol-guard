"""Bounded, fail-closed discovery of primary skill documents, owned by the runtime."""

from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.native_skill_directory_identity import (
    native_discover_skill_documents,
    portable_python_required,
)
from codex_plugin_scanner.guard.portable_skill_directory_discovery import (
    discover_skill_documents as portable_discover_skill_documents,
)
from codex_plugin_scanner.guard.skill_directory_identity_contract import (
    DEFAULT_SKILL_DIRECTORY_LIMITS,
    SkillDirectoryIdentityLimits,
    SkillDocumentDiscovery,
    _validate_limits,
)


def discover_skill_documents(
    skill_root: Path,
    *,
    limits: SkillDirectoryIdentityLimits = DEFAULT_SKILL_DIRECTORY_LIMITS,
) -> SkillDocumentDiscovery:
    """Discover primary documents without following links or exceeding limits.

    Discovery stops descending once a directory contains ``SKILL.md``; the
    identity inspector owns that complete subtree. Any unreadable, linked, or
    over-budget grouping path becomes a typed issue carrying its own
    non-reusable identity, so callers emit one artifact instead of silently
    omitting unknown content.
    """

    _validate_limits(limits)
    root = Path(skill_root)
    if portable_python_required(root):
        return portable_discover_skill_documents(root, limits=limits)
    return native_discover_skill_documents(root, limits=limits)
