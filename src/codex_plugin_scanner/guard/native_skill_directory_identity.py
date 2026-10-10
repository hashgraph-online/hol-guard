"""Skill-directory identity and discovery from the native runtime.

The resident walks the skill tree, hashes it, and discovers primary skill
documents. Python sends absolute paths and resource ceilings and presents the
answer. Every digest, incomplete-state hash, and discovery issue id arrives
from the runtime bound to the exact request; nothing here recomputes one.

Two cases never reach the runtime: Windows, where the resident has no skill
op and the portable Python implementation keeps its locked-descriptor and
reparse-point handling, and paths that JSON cannot carry byte-for-byte
(non-UTF-8 POSIX names), which the Rust request parser would reject.

When no bound answer is available the result is an explicit, non-reusable
``native_unavailable`` identity. Its state hash and the discovery issue id are
fixed constants pinned against the runtime's own hashing material by a
runtime test, so even the unavailable path never derives a hash in Python.
"""

from __future__ import annotations

import os
import re
from collections.abc import Mapping
from pathlib import Path
from typing import TypeGuard, get_args
from uuid import uuid4

from .native_context import _canonical_request_sha256, _resolve_digest_home, ensure_resident_prerequisite
from .native_execution import _resident_request
from .native_path_anchor import anchor_to_process_directory
from .skill_directory_identity_contract import (
    SKILL_DIRECTORY_IDENTITY_SCHEMA,
    SkillDirectoryIdentity,
    SkillDirectoryIdentityFailure,
    SkillDirectoryIdentityLimits,
    SkillDocumentDiscovery,
    SkillDocumentDiscoveryIssue,
)

SKILL_DIRECTORY_IDENTITY_FEATURE = "skill-directory-identity-v1"
_REQUEST_SCHEMA = "guard-skill-directory-identity-request.v1"
_RESULT_SCHEMA = "guard-skill-directory-identity-result.v1"
_INSPECT_TIMEOUT_SECONDS = 60.0
_DISCOVER_TIMEOUT_SECONDS = 30.0
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
_DISCOVERY_KEYS = frozenset({"documents_hex", "issues"})

# Pinned by ``transport_unavailable_constants_are_pinned`` in the runtime.
_UNAVAILABLE_STATE_HASH = "sha256:996f4946b4e5880a4f6760d4ea1ad25d81dfe288ed8a51394ce8cb30c980a49c"
_UNAVAILABLE_ISSUE_ID = "a032a4986b3448cf"


def _is_windows() -> bool:
    return os.name == "nt"


def portable_python_required(*paths: Path) -> bool:
    """True where the native op cannot serve the request: Windows or non-UTF-8 paths."""

    if _is_windows():
        return True
    for path in paths:
        try:
            _ = os.fsencode(path).decode("utf-8")
        except UnicodeError:
            return True
    return False


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
            "kind": "inspect",
            "skill_document": anchor_to_process_directory(skill_document),
            "scope_root": anchor_to_process_directory(scope_root),
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
        {"kind": "discover", "skill_root": str(root), "limits": _limits(limits)},
        timeout_seconds=_DISCOVER_TIMEOUT_SECONDS,
    )
    discovery = _decode_discovery(payload, root)
    if discovery is not None:
        return discovery
    try:
        _ = os.lstat(root)
    except FileNotFoundError:
        # Nothing exists to enumerate, matching the runtime's own NotFound
        # answer; an absent harness must not look installed or incomplete.
        return SkillDocumentDiscovery(documents=(), issues=())
    except OSError:
        pass
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


def _exchange(command: dict[str, object], *, timeout_seconds: float) -> object | None:
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
    if not ensure_resident_prerequisite(guard_home):
        return None
    response = _resident_request(
        operation="skill_directory_identity",
        request=request,
        guard_home=guard_home,
        timeout_seconds=timeout_seconds,
        required_feature=SKILL_DIRECTORY_IDENTITY_FEATURE,
        response_schema=_RESULT_SCHEMA,
    )
    if (
        response is None
        or response.get("schema") != _RESULT_SCHEMA
        or response.get("request_id") != request["request_id"]
        or response.get("request_sha256") != digest
        or response.get("status") != "ok"
        or response.get("code") != "ok"
    ):
        return None
    return response.get("payload")


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
    if text.startswith("/") or any(part in {"", ".", ".."} for part in parts):
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
    "native_discover_skill_documents",
    "native_inspect_skill_directory",
    "portable_python_required",
    "unavailable_skill_directory_identity",
]
