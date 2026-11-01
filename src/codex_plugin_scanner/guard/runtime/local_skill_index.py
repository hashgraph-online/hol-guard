"""Explicitly scoped skill metadata discovery; no loading or grant writes.

The runtime's ``local-skill-index`` command discovers the primary skill
documents below each approved root, reads their bounded frontmatter and
hashes one skill's directory on inspection. This module keeps the records the
daemon pages through and maps the runtime's static issue codes.
"""

from __future__ import annotations

import hashlib
import os
import threading
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from ..mdm.runtime_request import runtime_answer
from .false_positive_rules import KNOWN_SKILL_DOC_ROOT_SUFFIXES

_FEATURE = "native-local-skill-index-v1"
_COMMAND = "local-skill-index"
_SCHEMA = "local-skill-index.v1"
_INDEX_TIMEOUT_SECONDS = 60.0
_INSPECT_TIMEOUT_SECONDS = 30.0
_INDEX_OUTPUT_LIMIT = 32 * 1024 * 1024
_INSPECT_OUTPUT_LIMIT = 64 * 1024
_PATH_ENCODING = "utf16le" if os.name == "nt" else "os_bytes"
_IDENTITY_KEYS = {"status", "manifest_digest", "entry_count", "total_bytes", "reason"}


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


def _encoded(path: Path) -> str:
    text = str(path)
    return (text.encode("utf-16-le", "surrogatepass") if os.name == "nt" else os.fsencode(text)).hex()


def _relative(value: object) -> str | None:
    """A runtime-reported document path strictly below its root."""

    if not isinstance(value, str) or not value:
        return None
    try:
        text = os.fsdecode(bytes.fromhex(value))
    except ValueError:
        return None
    parts = text.split("/")
    if text.startswith("/") or any(part in {"", ".", ".."} for part in parts):
        return None
    if os.name == "nt" and ("\\" in text or ":" in text):
        return None
    return text


def _skill_index_answer(request: dict[str, object], *, output_limit: int, timeout: float) -> dict[str, object] | None:
    return runtime_answer(
        _FEATURE,
        _COMMAND,
        {"schema": _SCHEMA, "path_encoding": _PATH_ENCODING, **request},
        output_limit=output_limit,
        timeout_seconds=timeout,
    )


def index_local_skills(
    roots: dict[str, Path],
    *,
    home: Path,
    cancel: threading.Event,
) -> tuple[dict[str, LocalSkillRecord], list[dict[str, str]]]:
    """Index every approved root's skill metadata in one runtime request."""

    if cancel.is_set() or not roots:
        return {}, []
    answer = _skill_index_answer(
        {
            "op": "index",
            "home_hex": _encoded(home),
            "roots": [{"root_id": root_id, "root_hex": _encoded(root)} for root_id, root in roots.items()],
        },
        output_limit=_INDEX_OUTPUT_LIMIT,
        timeout=_INDEX_TIMEOUT_SECONDS,
    )
    raw_records = answer.get("records") if answer is not None else None
    raw_issues = answer.get("issues") if answer is not None else None
    if not isinstance(raw_records, list) or not isinstance(raw_issues, list):
        return {}, [{"root_id": root_id, "reason": "skill-index-unavailable"} for root_id in roots]
    records: dict[str, LocalSkillRecord] = {}
    issues: list[dict[str, str]] = []
    for raw in raw_issues:
        root_id = raw.get("root_id") if isinstance(raw, dict) else None
        reason = raw.get("reason") if isinstance(raw, dict) else None
        if root_id in roots and isinstance(reason, str):
            issues.append({"root_id": str(root_id), "reason": reason})
    for raw in raw_records:
        root_id = raw.get("root_id") if isinstance(raw, dict) else None
        metadata = raw.get("metadata") if isinstance(raw, dict) else None
        relative = _relative(raw.get("document_hex")) if isinstance(raw, dict) else None
        if not isinstance(root_id, str) or root_id not in roots or not isinstance(metadata, dict) or relative is None:
            issues.append({"root_id": str(root_id) if root_id in roots else "", "reason": "metadata-unreadable"})
            continue
        root = roots[root_id]
        skill_id = hashlib.sha256((str(root) + "\0" + relative).encode()).hexdigest()
        records[skill_id] = LocalSkillRecord(skill_id, root_id, root / relative, root, metadata)
    return records, issues


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
    """Hash the indexed skill's directory, refusing metadata that moved since indexing."""

    answer = _skill_index_answer(
        {
            "op": "inspect",
            "home_hex": _encoded(home),
            "root_hex": _encoded(record.root),
            "document_hex": _encoded(record.document),
            "metadata_digest": record.metadata["metadata_digest"],
        },
        output_limit=_INSPECT_OUTPUT_LIMIT,
        timeout=_INSPECT_TIMEOUT_SECONDS,
    )
    if answer is None:
        raise OSError("skill-inspection-unavailable")
    error = answer.get("error")
    if isinstance(error, str) and error:
        raise ValueError(error)
    identity = answer.get("identity")
    if not isinstance(identity, dict) or set(identity) != _IDENTITY_KEYS:
        raise OSError("skill-inspection-unavailable")
    return {
        "skill_id": record.skill_id,
        "status": identity["status"],
        "manifest_digest": identity["manifest_digest"],
        "entry_count": identity["entry_count"],
        "total_bytes": identity["total_bytes"],
        "reason": identity["reason"],
        "requirements_complete": False,
        "permissions_granted": False,
        "runtime_checks_required": True,
    }
