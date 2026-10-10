"""Explicitly scoped skill metadata discovery; no loading or grant writes."""

from __future__ import annotations

import hashlib
import os
import re
import stat
import threading
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from ..adapters.hermes_file_inspection import parse_hermes_yaml_mapping
from ..file_identity import full_stat_identity
from ..path_security import path_has_symlink_component
from ..skill_directory_discovery import discover_skill_documents
from ..skill_directory_identity import inspect_skill_directory
from ..skill_directory_identity_contract import SkillDirectoryIdentityLimits
from ..windows_paths import open_windows_locked_regular_descriptor
from .false_positive_rules import KNOWN_SKILL_DOC_ROOT_SUFFIXES
from .skill_workflow_preflight import parse_guard_skill_dependencies

_HEADER_BYTES = 16_384
_INDEX_LIMIT = 1000
_DISCOVERY_LIMITS = SkillDirectoryIdentityLimits(max_depth=8, max_entries=1024)
_INSPECTION_LIMITS = SkillDirectoryIdentityLimits(
    max_depth=16,
    max_entries=4096,
    max_file_bytes=16 * 1024 * 1024,
    max_total_bytes=16 * 1024 * 1024,
)
_NAME = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*\Z")


@dataclass(frozen=True)
class LocalSkillRecord:
    skill_id: str
    root_id: str
    document: Path
    root: Path
    metadata: dict[str, object]

    def public(self, *, duplicate: bool = False) -> dict[str, object]:
        return {
            "skill_id": self.skill_id,
            "root_id": self.root_id,
            "origin": "local-agent-skill",
            "uri": self.document.as_uri(),
            "duplicate_name": duplicate,
            "permission_state": "not-granted",
            **self.metadata,
        }


def approved_skill_roots(home: Path) -> dict[str, Path]:
    # The API offers these fixed harness locations; it never accepts an
    # arbitrary client path. Reading them still requires explicit selection.
    return {hashlib.sha256(suffix.encode()).hexdigest(): home / suffix for suffix in KNOWN_SKILL_DOC_ROOT_SUFFIXES}


def index_local_skills(
    roots: dict[str, Path],
    *,
    home: Path,
    cancel: threading.Event,
) -> tuple[dict[str, LocalSkillRecord], list[dict[str, str]]]:
    records: dict[str, LocalSkillRecord] = {}
    issues: list[dict[str, str]] = []
    for root_id, root in roots.items():
        if cancel.is_set():
            break
        if path_has_symlink_component(root, allowed_root=home):
            issues.append({"root_id": root_id, "reason": "linked-root-not-indexed"})
            continue
        discovery = discover_skill_documents(root, limits=_DISCOVERY_LIMITS)
        issues.extend({"root_id": root_id, "reason": issue.failure_reason} for issue in discovery.issues)
        for document in discovery.documents:
            if cancel.is_set():
                break
            if len(records) >= _INDEX_LIMIT:
                issues.append({"root_id": root_id, "reason": "skill-index-limit"})
                return records, issues
            skill_id = hashlib.sha256((str(root) + "\0" + document.relative_to(root).as_posix()).encode()).hexdigest()
            try:
                metadata = read_skill_metadata(document, root=root)
            except (OSError, ValueError) as error:
                # Narrow static codes only; never return raw file/parser data.
                code = str(error) if isinstance(error, ValueError) else "metadata-unreadable"
                issues.append({"root_id": root_id, "reason": code})
                continue
            records[skill_id] = LocalSkillRecord(skill_id, root_id, document, root, metadata)
    return records, issues


def read_skill_metadata(document: Path, *, root: Path) -> dict[str, object]:
    if path_has_symlink_component(document, allowed_root=root):
        raise ValueError("linked-skill-not-indexed")
    before = os.lstat(document)
    if not stat.S_ISREG(before.st_mode):
        raise ValueError("metadata-not-regular-file")
    descriptor = (
        open_windows_locked_regular_descriptor(document)
        if os.name == "nt"
        else os.open(document, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    )
    try:
        opened = os.fstat(descriptor)
        if os.name != "nt" and full_stat_identity(opened) != full_stat_identity(before):
            raise ValueError("metadata-changed-during-read")
        raw = os.read(descriptor, _HEADER_BYTES + 1)
        if full_stat_identity(os.fstat(descriptor)) != full_stat_identity(opened):
            raise ValueError("metadata-changed-during-read")
        if full_stat_identity(os.lstat(document)) != full_stat_identity(before):
            raise ValueError("metadata-changed-during-read")
    finally:
        os.close(descriptor)
    lines = raw[:_HEADER_BYTES].splitlines(keepends=True)
    if not lines or lines[0].strip() != b"---":
        raise ValueError("metadata-frontmatter-missing")
    end = next((index for index, line in enumerate(lines[1:], 1) if line.strip() == b"---"), None)
    if end is None:
        raise ValueError("metadata-frontmatter-limit")
    try:
        header = b"".join(lines[1:end]).decode("utf-8")
    except UnicodeError as error:
        raise ValueError("metadata-invalid-utf8") from error
    parsed = parse_hermes_yaml_mapping(header)
    if parsed is None:
        raise ValueError("metadata-invalid-frontmatter")
    name, description = parsed.get("name"), parsed.get("description")
    if (
        not isinstance(name, str)
        or len(name) > 64
        or not _NAME.fullmatch(name)
        or name != document.parent.name
        or not isinstance(description, str)
        or not 1 <= len(description.strip()) <= 1024
    ):
        raise ValueError("metadata-invalid-name-or-description")
    compatibility, requested = parsed.get("compatibility", ""), parsed.get("allowed-tools", "")
    if not isinstance(compatibility, str) or len(compatibility) > 500:
        raise ValueError("metadata-invalid-compatibility")
    if not isinstance(requested, str) or len(requested) > 2048:
        raise ValueError("metadata-invalid-tool-request")
    return {
        "name": name,
        "description": description.strip(),
        "compatibility": compatibility,
        "requested_tools": requested,
        "metadata_digest": hashlib.sha256(header.encode()).hexdigest(),
        "requirements_complete": False,
        "instruction_content_loaded": False,
        "dependencies": parse_guard_skill_dependencies(parsed),
    }


def public_skill_page(
    records: dict[str, LocalSkillRecord],
    *,
    offset: int,
    search: str,
) -> dict[str, object]:
    names = Counter(str(record.metadata["name"]) for record in records.values())
    selected = sorted(
        (
            record
            for record in records.values()
            if search.casefold() in f"{record.metadata['name']} {record.metadata['description']}".casefold()
        ),
        key=lambda record: (str(record.metadata["name"]), record.skill_id),
    )
    return {
        "skills": [
            record.public(duplicate=names[str(record.metadata["name"])] > 1)
            for record in selected[offset : offset + 50]
        ],
        "known_count": len(records),
        "matched_count": len(selected),
        "next_offset": offset + 50 if offset + 50 < len(selected) else None,
        "permissions_granted": False,
    }


def inspect_indexed_skill(record: LocalSkillRecord, *, home: Path) -> dict[str, object]:
    if path_has_symlink_component(record.document, allowed_root=home):
        raise ValueError("linked-skill-not-inspected")
    current = read_skill_metadata(record.document, root=record.root)
    if current["metadata_digest"] != record.metadata["metadata_digest"]:
        raise ValueError("skill-metadata-changed")
    identity = inspect_skill_directory(record.document, scope_root=record.root, limits=_INSPECTION_LIMITS)
    if read_skill_metadata(record.document, root=record.root)["metadata_digest"] != current["metadata_digest"]:
        raise ValueError("skill-metadata-changed")
    return {
        "skill_id": record.skill_id,
        "status": identity.status,
        "manifest_digest": identity.directory_hash,
        "entry_count": identity.entry_count,
        "total_bytes": identity.total_bytes,
        "reason": identity.failure_reason,
        "requirements_complete": False,
        "permissions_granted": False,
        "runtime_checks_required": True,
    }
