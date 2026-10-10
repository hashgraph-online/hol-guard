"""Portable-Python helpers for the skill directory identity fallback used where the native op is unavailable."""

from __future__ import annotations

import hashlib
import json
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Protocol

from codex_plugin_scanner.guard.skill_directory_identity_contract import (
    SKILL_DIRECTORY_IDENTITY_SCHEMA,
    SkillDirectoryIdentity,
    SkillDirectoryIdentityFailure,
)


@dataclass(frozen=True, slots=True)
class _TreeEntry:
    path: Path
    relative_path: str
    entry_type: Literal["directory", "file", "symlink"]
    metadata_key: tuple[int, ...]
    raw_link_target: str | None = None


@dataclass(slots=True)
class _InspectionState:
    entry_count: int = 0
    total_bytes: int = 0
    primary_content_hash: str | None = None


class _Digest(Protocol):
    def update(self, data: bytes, /) -> None: ...


class _IncompleteIdentityError(Exception):
    def __init__(self, reason: SkillDirectoryIdentityFailure) -> None:
        super().__init__(reason)
        self.reason: SkillDirectoryIdentityFailure = reason


def _canonical_component(value: str) -> str:
    _validate_text_path(value)
    normalized = unicodedata.normalize("NFC", value)
    if normalized in {"", ".", ".."} or "/" in normalized or "\\" in normalized:
        raise _IncompleteIdentityError("invalid_relative_path")
    return normalized


def _canonical_relative_path(parts: tuple[str, ...]) -> str:
    return "/".join(_canonical_component(part) for part in parts)


def _validate_text_path(value: str) -> None:
    if any(0xD800 <= ord(character) <= 0xDFFF for character in value):
        raise _IncompleteIdentityError("invalid_path_encoding")


def _update_canonical_digest(digest: _Digest, record: dict[str, object]) -> None:
    encoded = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    digest.update(encoded)
    digest.update(b"\n")


def _incomplete_result(
    state: _InspectionState,
    reason: SkillDirectoryIdentityFailure,
) -> SkillDirectoryIdentity:
    provisional = SkillDirectoryIdentity(
        schema_version=SKILL_DIRECTORY_IDENTITY_SCHEMA,
        status="incomplete",
        directory_hash=None,
        primary_content_hash=state.primary_content_hash,
        entry_count=state.entry_count,
        total_bytes=state.total_bytes,
        failure_reason=reason,
        incomplete_state_hash=None,
    )
    return SkillDirectoryIdentity(
        schema_version=provisional.schema_version,
        status=provisional.status,
        directory_hash=None,
        primary_content_hash=provisional.primary_content_hash,
        entry_count=provisional.entry_count,
        total_bytes=provisional.total_bytes,
        failure_reason=provisional.failure_reason,
        incomplete_state_hash=_incomplete_state_hash(provisional),
    )


def incomplete_skill_directory_identity(
    reason: SkillDirectoryIdentityFailure,
) -> SkillDirectoryIdentity:
    """Create a stable, explicitly non-reusable identity for discovery gaps."""

    return _incomplete_result(_InspectionState(), reason)


def _incomplete_state_hash(identity: SkillDirectoryIdentity) -> str:
    material = {
        "schema": identity.schema_version,
        "status": "incomplete",
        "reason": identity.failure_reason,
        "primaryContentHash": identity.primary_content_hash,
        "entryCount": identity.entry_count,
        "totalBytes": identity.total_bytes,
    }
    digest = hashlib.sha256(json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8"))
    return f"sha256:{digest.hexdigest()}"
