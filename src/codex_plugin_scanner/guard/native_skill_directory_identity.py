"""Skill-directory identity and discovery from the native runtime.

The resident walks the skill tree, hashes it, and discovers primary skill
documents. Python sends absolute paths and resource ceilings and presents the
answer. Every digest, incomplete-state hash, and discovery issue id arrives
from the runtime bound to the exact request; nothing here recomputes one.

Paths use an OS-specific byte encoding, including non-UTF8 POSIX names and
Windows UTF-16 names. The native walker owns every platform path decision.

When no bound answer is available the result is an explicit, non-reusable
``native_unavailable`` identity. Its state hash and the discovery issue id are
fixed constants pinned against the runtime's own hashing material by a
runtime test, so inspection and discovery never derive a hash in Python.
The compatibility constructor for a caller-supplied incomplete reason uses
the same canonical JSON material as the runtime when the runtime does not
answer, and it keeps that reason.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import time
from collections.abc import Mapping
from pathlib import Path
from typing import TypeGuard, get_args
from uuid import uuid4

from .native_context import (
    _canonical_request_sha256,
    _resolve_digest_home,
    ensure_resident_prerequisite,
)
from .native_execution import _resident_request
from .native_path_anchor import anchor_to_process_directory
from .native_runtime import native_runtime_status
from .skill_directory_identity_contract import (
    SKILL_DIRECTORY_IDENTITY_SCHEMA,
    SkillDirectoryIdentity,
    SkillDirectoryIdentityFailure,
    SkillDirectoryIdentityLimits,
    SkillDocumentDiscovery,
    SkillDocumentDiscoveryIssue,
)

SKILL_DIRECTORY_IDENTITY_FEATURE = "skill-directory-identity-v1"
SKILL_DOCUMENT_EVIDENCE_FEATURE = "skill-document-evidence-v1"
_REQUEST_SCHEMA = "guard-skill-directory-identity-request.v1"
_RESULT_SCHEMA = "guard-skill-directory-identity-result.v1"
_INSPECT_TIMEOUT_SECONDS = 60.0
_DISCOVER_TIMEOUT_SECONDS = 30.0
_INCOMPLETE_TIMEOUT_SECONDS = 2.0
_DOCUMENT_EVIDENCE_TIMEOUT_SECONDS = 15.0
SKILL_DOCUMENT_EVIDENCE_SCHEMA = "guard.skill.content-evidence.v1"
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_ISSUE_ID = re.compile(r"^[0-9a-f]{16}$")
_FAILURES = frozenset(get_args(SkillDirectoryIdentityFailure)) - {"native_unavailable"}
_IDENTITY_KEYS = frozenset(
    {
        "schema_version",
        "status",
        "directory_hash",
        "primary_content_hash",
        "entry_count",
        "total_bytes",
        "failure_reason",
        "incomplete_state_hash",
    }
)
_ISSUE_KEYS = frozenset({"relative_path_hex", "failure_reason", "issue_id", "identity"})
_DOCUMENT_EVIDENCE_KEYS = frozenset(
    {
        "readability_status",
        "byte_length",
        "content_hash",
        "line_count",
        "heading_count",
        "frontmatter_present",
        "documented_network_capability",
    }
)
_DOCUMENT_READABILITY = frozenset(
    {
        "not_primary_skill_document",
        "symlink_rejected",
        "unreadable",
        "outside_safe_roots",
        "not_regular_file",
        "too_large",
        "invalid_utf8",
        "readable",
    }
)
_DOCUMENTED_CAPABILITY_CODES = frozenset({"explicit_http_client", "explicit_remote_api_statement"})
_DISCOVERY_KEYS = frozenset({"documents_hex", "issues"})

# Pinned by ``transport_unavailable_constants_are_pinned`` in the runtime.
_UNAVAILABLE_STATE_HASH = "sha256:996f4946b4e5880a4f6760d4ea1ad25d81dfe288ed8a51394ce8cb30c980a49c"
_UNAVAILABLE_ISSUE_ID = "a032a4986b3448cf"


def _is_windows() -> bool:
    return os.name == "nt"


def _encoded_path(path: Path) -> str:
    text = anchor_to_process_directory(path)
    return (text.encode("utf-16-le", "surrogatepass") if _is_windows() else os.fsencode(text)).hex()


def _encoded_text(text: str) -> str:
    """Encode a path without anchoring it, for a command that sends the cwd."""

    return (text.encode("utf-16-le", "surrogatepass") if _is_windows() else os.fsencode(text)).hex()


def unavailable_skill_directory_identity() -> SkillDirectoryIdentity:
    """Non-reusable identity reported when the runtime gives no bound answer."""

    return SkillDirectoryIdentity(
        schema_version=SKILL_DIRECTORY_IDENTITY_SCHEMA,
        status="incomplete",
        directory_hash=None,
        primary_content_hash=None,
        entry_count=0,
        total_bytes=0,
        failure_reason="native_unavailable",
        incomplete_state_hash=_UNAVAILABLE_STATE_HASH,
    )


def native_inspect_skill_directory(
    skill_document: Path,
    *,
    scope_root: Path,
    limits: SkillDirectoryIdentityLimits,
) -> SkillDirectoryIdentity:
    payload = _exchange(
        {
            "kind": "inspect_encoded",
            "skill_document_hex": _encoded_path(skill_document),
            "scope_root_hex": _encoded_path(scope_root),
            "path_encoding": "utf16le" if _is_windows() else "os_bytes",
            "limits": _limits(limits),
        },
        timeout_seconds=_INSPECT_TIMEOUT_SECONDS,
    )
    identity = _decode_identity(payload)
    return identity if identity is not None else unavailable_skill_directory_identity()


def native_discover_skill_documents(
    skill_root: Path,
    *,
    limits: SkillDirectoryIdentityLimits,
) -> SkillDocumentDiscovery:
    root = Path(anchor_to_process_directory(skill_root))
    payload = _exchange(
        {
            "kind": "discover_encoded",
            "skill_root_hex": _encoded_path(root),
            "path_encoding": "utf16le" if _is_windows() else "os_bytes",
            "limits": _limits(limits),
        },
        timeout_seconds=_DISCOVER_TIMEOUT_SECONDS,
    )
    discovery = _decode_discovery(payload, root)
    if discovery is not None:
        return discovery
    return SkillDocumentDiscovery(
        documents=(),
        issues=(
            SkillDocumentDiscoveryIssue(
                path=root,
                relative_path=".",
                failure_reason="native_unavailable",
                issue_id=_UNAVAILABLE_ISSUE_ID,
                identity=unavailable_skill_directory_identity(),
            ),
        ),
    )


def _limits(limits: SkillDirectoryIdentityLimits) -> dict[str, object]:
    return {
        "max_depth": limits.max_depth,
        "max_entries": limits.max_entries,
        "max_file_bytes": limits.max_file_bytes,
        "max_total_bytes": limits.max_total_bytes,
    }


def native_incomplete_skill_directory_identity(reason: SkillDirectoryIdentityFailure) -> SkillDirectoryIdentity:
    payload = _exchange(
        {"kind": "incomplete", "reason": reason},
        timeout_seconds=_INCOMPLETE_TIMEOUT_SECONDS,
    )
    identity = _decode_identity(payload)
    if identity is not None and identity.failure_reason == reason:
        return identity
    return _caller_incomplete_identity(reason)


def _caller_incomplete_identity(reason: SkillDirectoryIdentityFailure) -> SkillDirectoryIdentity:
    """Zero-progress identity for a reason the caller already decided.

    The digest matches ``incomplete_state_hash_for_label`` (CPython canonical
    JSON). A missing runtime must not relabel that reason as
    ``native_unavailable``.
    """

    material = {
        "schema": SKILL_DIRECTORY_IDENTITY_SCHEMA,
        "status": "incomplete",
        "reason": reason,
        "primaryContentHash": None,
        "entryCount": 0,
        "totalBytes": 0,
    }
    encoded = json.dumps(material, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    return SkillDirectoryIdentity(
        schema_version=SKILL_DIRECTORY_IDENTITY_SCHEMA,
        status="incomplete",
        directory_hash=None,
        primary_content_hash=None,
        entry_count=0,
        total_bytes=0,
        failure_reason=reason,
        incomplete_state_hash="sha256:" + hashlib.sha256(encoded).hexdigest(),
    )


def _exchange(
    command: dict[str, object],
    *,
    timeout_seconds: float,
    required_feature: str = SKILL_DIRECTORY_IDENTITY_FEATURE,
) -> object | None:
    deadline = time.monotonic() + timeout_seconds
    guard_home = _resolve_digest_home(None)
    request: dict[str, object] = {
        "schema": _REQUEST_SCHEMA,
        "request_id": f"skill-directory-identity-{uuid4().hex}",
        "guard_home": str(guard_home),
        "command": command,
    }
    try:
        digest = "sha256:" + _canonical_request_sha256(request)
    except (TypeError, ValueError):
        return None
    status = native_runtime_status(deadline_monotonic=deadline)
    if not status.available or not status.compatible or time.monotonic() >= deadline:
        return None
    if not ensure_resident_prerequisite(guard_home):
        return None
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return None
    response = _resident_request(
        operation="skill_directory_identity",
        request=request,
        guard_home=guard_home,
        timeout_seconds=remaining,
        required_feature=required_feature,
        response_schema=_RESULT_SCHEMA,
        status=status,
    )
    if (
        response is None
        or time.monotonic() > deadline
        or response.get("schema") != _RESULT_SCHEMA
        or response.get("request_id") != request["request_id"]
        or response.get("request_sha256") != digest
        or response.get("status") != "ok"
        or response.get("code") != "ok"
    ):
        return None
    return response.get("payload")


def native_skill_document_evidence(
    skill_document: object,
    *,
    safe_roots: tuple[Path | None, ...],
) -> dict[str, object] | None:
    """Bounded evidence for one primary skill document, read by the runtime.

    The document path travels exactly as the caller holds it, with the caller's
    working directory alongside, so the runtime reads the same components the
    caller sees and anchors a relative path the same way. ``None`` means no
    bound answer arrived; the caller reports its own unavailable evidence.
    """

    if not isinstance(skill_document, str) or not skill_document:
        return None
    try:
        process_directory = os.getcwd()
    except OSError:
        # A process whose working directory has been removed has no directory
        # to anchor a relative document against, and the caller's own
        # unavailable evidence is the answer that leaves.
        return None
    encoding = "utf16le" if _is_windows() else "os_bytes"
    roots = [root for root in safe_roots if root is not None]
    payload = _exchange(
        {
            "kind": "document_evidence",
            "skill_document_hex": _encoded_text(skill_document),
            "process_directory_hex": _encoded_path(Path(process_directory)),
            "safe_roots_hex": [_encoded_path(root) for root in roots],
            "path_encoding": encoding,
        },
        timeout_seconds=_DOCUMENT_EVIDENCE_TIMEOUT_SECONDS,
        required_feature=SKILL_DOCUMENT_EVIDENCE_FEATURE,
    )
    return _decode_document_evidence(payload)


def _decode_document_evidence(payload: object) -> dict[str, object] | None:
    if not isinstance(payload, Mapping) or set(payload) != _DOCUMENT_EVIDENCE_KEYS:
        return None
    status = payload["readability_status"]
    if status not in _DOCUMENT_READABILITY:
        return None
    byte_length = payload["byte_length"]
    if byte_length is not None and not _is_count(byte_length):
        return None
    evidence: dict[str, object] = {"readabilityStatus": status}
    if byte_length is not None:
        evidence["byteLength"] = byte_length
    if status != "readable":
        return evidence
    content_hash = payload["content_hash"]
    line_count = payload["line_count"]
    heading_count = payload["heading_count"]
    frontmatter = payload["frontmatter_present"]
    if (
        not _is_sha256(content_hash)
        or byte_length is None
        or not _is_count(line_count)
        or not _is_count(heading_count)
        or not isinstance(frontmatter, bool)
    ):
        return None
    capability = payload["documented_network_capability"]
    if capability is not None and capability not in _DOCUMENTED_CAPABILITY_CODES:
        return None
    evidence.update(
        {
            "schemaVersion": SKILL_DOCUMENT_EVIDENCE_SCHEMA,
            "contentHash": content_hash,
            "lineCount": line_count,
            "headingCount": heading_count,
            "frontmatterPresent": frontmatter,
            "truncatedForAnalysis": False,
        }
    )
    if capability is not None:
        evidence["documentedNetworkCapability"] = capability
    return evidence


def _is_count(value: object) -> TypeGuard[int]:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _is_failure(value: object) -> TypeGuard[SkillDirectoryIdentityFailure]:
    return isinstance(value, str) and value in _FAILURES


def _is_sha256(value: object) -> TypeGuard[str]:
    return isinstance(value, str) and _SHA256.fullmatch(value) is not None


def _decode_identity(payload: object) -> SkillDirectoryIdentity | None:
    if not isinstance(payload, Mapping) or set(payload) != _IDENTITY_KEYS:
        return None
    status = payload["status"]
    directory_hash = payload["directory_hash"]
    primary_hash = payload["primary_content_hash"]
    reason = payload["failure_reason"]
    state_hash = payload["incomplete_state_hash"]
    entry_count = payload["entry_count"]
    total_bytes = payload["total_bytes"]
    if payload["schema_version"] != SKILL_DIRECTORY_IDENTITY_SCHEMA:
        return None
    if not _is_count(entry_count) or not _is_count(total_bytes):
        return None
    if primary_hash is not None and not _is_sha256(primary_hash):
        return None
    if status == "complete":
        if not _is_sha256(directory_hash) or not _is_sha256(primary_hash):
            return None
        if reason is not None or state_hash is not None:
            return None
        return SkillDirectoryIdentity(
            schema_version=SKILL_DIRECTORY_IDENTITY_SCHEMA,
            status="complete",
            directory_hash=directory_hash,
            primary_content_hash=primary_hash,
            entry_count=entry_count,
            total_bytes=total_bytes,
            failure_reason=None,
            incomplete_state_hash=None,
        )
    if status == "incomplete":
        if directory_hash is not None or not _is_failure(reason) or not _is_sha256(state_hash):
            return None
        return SkillDirectoryIdentity(
            schema_version=SKILL_DIRECTORY_IDENTITY_SCHEMA,
            status="incomplete",
            directory_hash=None,
            primary_content_hash=primary_hash,
            entry_count=entry_count,
            total_bytes=total_bytes,
            failure_reason=reason,
            incomplete_state_hash=state_hash,
        )
    return None


def _relative(value: object) -> str | None:
    """Decode a runtime-supplied hex path; refuse anything not strictly below."""

    if not isinstance(value, str) or not value:
        return None
    try:
        text = os.fsdecode(bytes.fromhex(value))
    except ValueError:
        return None
    if text == ".":
        return text
    parts = text.split("/")
    if (
        text.startswith("/")
        or any(part in {"", ".", ".."} for part in parts)
        or (_is_windows() and ("\\" in text or ":" in text))
    ):
        return None
    return text


def _decode_discovery(payload: object, root: Path) -> SkillDocumentDiscovery | None:
    if not isinstance(payload, Mapping) or set(payload) != _DISCOVERY_KEYS:
        return None
    documents_hex, issues_raw = payload["documents_hex"], payload["issues"]
    if not isinstance(documents_hex, list) or not isinstance(issues_raw, list):
        return None
    documents: list[Path] = []
    for item in documents_hex:
        relative = _relative(item)
        if relative is None or relative == ".":
            return None
        documents.append(root / relative)
    issues: list[SkillDocumentDiscoveryIssue] = []
    for raw in issues_raw:
        if not isinstance(raw, Mapping) or set(raw) != _ISSUE_KEYS:
            return None
        relative = _relative(raw["relative_path_hex"])
        identity = _decode_identity(raw["identity"])
        reason = raw["failure_reason"]
        issue_id = raw["issue_id"]
        if (
            relative is None
            or identity is None
            or not _is_failure(reason)
            or identity.failure_reason != reason
            or identity.status != "incomplete"
            or not isinstance(issue_id, str)
            or _ISSUE_ID.fullmatch(issue_id) is None
        ):
            return None
        issues.append(
            SkillDocumentDiscoveryIssue(
                path=root if relative == "." else root / relative,
                relative_path=relative,
                failure_reason=reason,
                issue_id=issue_id,
                identity=identity,
            )
        )
    return SkillDocumentDiscovery(documents=tuple(documents), issues=tuple(issues))


__all__ = [
    "SKILL_DIRECTORY_IDENTITY_FEATURE",
    "SKILL_DOCUMENT_EVIDENCE_FEATURE",
    "SKILL_DOCUMENT_EVIDENCE_SCHEMA",
    "native_discover_skill_documents",
    "native_inspect_skill_directory",
    "native_skill_document_evidence",
    "unavailable_skill_directory_identity",
]
