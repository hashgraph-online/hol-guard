"""Fail-closed identity for an agent skill directory, owned by the native runtime."""

from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.native_skill_directory_identity import (
    native_inspect_skill_directory,
    portable_python_required,
)
from codex_plugin_scanner.guard.portable_skill_directory_identity import (
    inspect_skill_directory as portable_inspect_skill_directory,
)
from codex_plugin_scanner.guard.skill_directory_discovery import discover_skill_documents
from codex_plugin_scanner.guard.skill_directory_identity_contract import (
    DEFAULT_SKILL_DIRECTORY_LIMITS,
    SKILL_DIRECTORY_IDENTITY_SCHEMA,
    SkillDirectoryIdentity,
    SkillDirectoryIdentityFailure,
    SkillDirectoryIdentityLimits,
    SkillDocumentDiscovery,
    SkillDocumentDiscoveryIssue,
    _validate_limits,
    skill_directory_identity_metadata,
    validated_complete_skill_directory_hash,
)


def inspect_skill_directory(
    skill_document: Path,
    *,
    scope_root: Path,
    limits: SkillDirectoryIdentityLimits = DEFAULT_SKILL_DIRECTORY_LIMITS,
) -> SkillDirectoryIdentity:
    """Return the runtime's complete canonical tree identity or a typed non-reusable result.

    The complete digest covers every filesystem entry below the skill root. A
    tree that cannot be inspected in full is never represented by a partial
    digest: it receives a typed stable state hash that cannot be reused as a
    complete identity. Python only transports the request; a missing or
    unbound runtime answer is a ``native_unavailable`` incomplete identity.
    Windows (no native op) and paths that cannot be carried as UTF-8 JSON use
    the portable Python implementation instead.
    """

    _validate_limits(limits)
    if portable_python_required(skill_document, scope_root):
        return portable_inspect_skill_directory(skill_document, scope_root=scope_root, limits=limits)
    return native_inspect_skill_directory(skill_document, scope_root=scope_root, limits=limits)


__all__ = [
    "DEFAULT_SKILL_DIRECTORY_LIMITS",
    "SKILL_DIRECTORY_IDENTITY_SCHEMA",
    "SkillDirectoryIdentity",
    "SkillDirectoryIdentityFailure",
    "SkillDirectoryIdentityLimits",
    "SkillDocumentDiscovery",
    "SkillDocumentDiscoveryIssue",
    "discover_skill_documents",
    "inspect_skill_directory",
    "skill_directory_identity_metadata",
    "validated_complete_skill_directory_hash",
]
