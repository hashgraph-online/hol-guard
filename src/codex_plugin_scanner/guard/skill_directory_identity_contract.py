"""Public data contract and metadata helpers for skill-directory identity."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

SKILL_DIRECTORY_IDENTITY_SCHEMA = "guard.skill-directory-identity.v1"

SkillDirectoryIdentityFailure = Literal[
    "root_missing",
    "root_not_directory",
    "primary_missing",
    "primary_symlink_unsupported",
    "invalid_relative_path",
    "invalid_path_encoding",
    "duplicate_path",
    "case_collision",
    "unreadable_entry",
    "special_file",
    "symlink_broken",
    "symlink_loop",
    "symlink_escape",
    "symlink_directory_unsupported",
    "unsupported_reparse_point",
    "max_depth_exceeded",
    "max_entries_exceeded",
    "max_file_bytes_exceeded",
    "max_total_bytes_exceeded",
    "tree_changed_during_hash",
    "native_unavailable",
]


@dataclass(frozen=True, slots=True)
class SkillDirectoryIdentityLimits:
    """Resource ceilings for a complete skill identity inspection."""

    max_depth: int = 32
    max_entries: int = 4096
    max_file_bytes: int = 128 * 1024 * 1024
    max_total_bytes: int = 256 * 1024 * 1024


DEFAULT_SKILL_DIRECTORY_LIMITS = SkillDirectoryIdentityLimits()


@dataclass(frozen=True, slots=True)
class SkillDirectoryIdentity:
    """Result of inspecting one primary skill document and its directory."""

    schema_version: str
    status: Literal["complete", "incomplete"]
    directory_hash: str | None
    primary_content_hash: str | None
    entry_count: int
    total_bytes: int
    failure_reason: SkillDirectoryIdentityFailure | None
    incomplete_state_hash: str | None


@dataclass(frozen=True, slots=True)
class SkillDocumentDiscoveryIssue:
    """One fail-closed gap encountered before a primary document was found."""

    path: Path
    relative_path: str
    failure_reason: SkillDirectoryIdentityFailure
    issue_id: str
    identity: SkillDirectoryIdentity


@dataclass(frozen=True, slots=True)
class SkillDocumentDiscovery:
    """Bounded skill-document discovery plus typed omitted-scope diagnostics."""

    documents: tuple[Path, ...]
    issues: tuple[SkillDocumentDiscoveryIssue, ...]


def skill_directory_identity_metadata(
    identity: SkillDirectoryIdentity,
    *,
    version_label: str,
) -> dict[str, object]:
    """Return artifact metadata that binds identity into inventory/approval flows."""

    envelope: dict[str, object] = {
        "schemaVersion": identity.schema_version,
        "status": identity.status,
        "entryCount": identity.entry_count,
        "totalBytes": identity.total_bytes,
        "reusable": identity.status == "complete",
    }
    metadata: dict[str, object] = {"skillDirectoryIdentity": envelope}
    if identity.primary_content_hash is not None:
        metadata["content_hash"] = identity.primary_content_hash

    if identity.status == "complete" and identity.directory_hash is not None:
        envelope["contentHash"] = identity.directory_hash
        metadata["directory_hash"] = identity.directory_hash
        version_hash = identity.directory_hash
    else:
        if identity.failure_reason is not None:
            envelope["reason"] = identity.failure_reason
        if identity.incomplete_state_hash is not None:
            envelope["incompleteStateHash"] = identity.incomplete_state_hash
        if identity.incomplete_state_hash is None:
            raise ValueError("an incomplete skill directory identity must carry its native state hash")
        version_hash = identity.incomplete_state_hash

    metadata["versionInfo"] = {
        "versionLabel": version_label,
        "hashBasis": "skill-directory-v1",
        "contentHash": version_hash,
        "changedFields": [],
    }
    return metadata


def validated_complete_skill_directory_hash(metadata: object) -> str | None:
    """Return the v1 directory digest only for a strict reusable envelope."""

    typed_metadata = _string_object_mapping(metadata)
    if typed_metadata is None:
        return None
    identity = typed_metadata.get("skillDirectoryIdentity")
    typed_identity = _string_object_mapping(identity)
    if typed_identity is None:
        return None
    if (
        typed_identity.get("schemaVersion") != SKILL_DIRECTORY_IDENTITY_SCHEMA
        or typed_identity.get("status") != "complete"
        or typed_identity.get("reusable") is not True
        or "reason" in typed_identity
        or "reuseNonce" in typed_identity
        or "incompleteStateHash" in typed_identity
    ):
        return None
    entry_count = typed_identity.get("entryCount")
    total_bytes = typed_identity.get("totalBytes")
    if (
        not isinstance(entry_count, int)
        or isinstance(entry_count, bool)
        or entry_count < 1
        or not isinstance(total_bytes, int)
        or isinstance(total_bytes, bool)
        or total_bytes < 0
    ):
        return None
    identity_hash = _canonical_sha256(typed_identity.get("contentHash"))
    directory_hash = _canonical_sha256(typed_metadata.get("directory_hash"))
    version_info = typed_metadata.get("versionInfo")
    typed_version_info = _string_object_mapping(version_info)
    if typed_version_info is None:
        return None
    if typed_version_info.get("hashBasis") != "skill-directory-v1":
        return None
    version_hash = _canonical_sha256(typed_version_info.get("contentHash"))
    if identity_hash is None or identity_hash != directory_hash or identity_hash != version_hash:
        return None
    return identity_hash


def _string_object_mapping(value: object) -> dict[str, object] | None:
    """Return a typed copy only when every runtime mapping key is a string."""

    if not isinstance(value, Mapping):
        return None
    result: dict[str, object] = {}
    for key, item in value.items():
        if not isinstance(key, str):
            return None
        result[key] = item
    return result


def _validate_limits(limits: SkillDirectoryIdentityLimits) -> None:
    values = (
        limits.max_depth,
        limits.max_entries,
        limits.max_file_bytes,
        limits.max_total_bytes,
    )
    if any(type(value) is not int or value < 0 for value in values):
        raise ValueError("skill directory identity limits must be non-negative integers")


def _canonical_sha256(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = value.strip().lower()
    if normalized.startswith("sha256:"):
        normalized = normalized.removeprefix("sha256:")
    if len(normalized) != 64 or any(character not in "0123456789abcdef" for character in normalized):
        return None
    return f"sha256:{normalized}"
