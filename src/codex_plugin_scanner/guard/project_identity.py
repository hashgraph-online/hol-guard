"""Portable project identity for cross-device Guard decision memory.

Project-scoped memory must not depend on where a repository is cloned on one
machine. The resident derives an opaque classification from the workspace's
Git metadata, keeping local filesystem paths out of the identity itself; this
module asks it and keeps only the metadata glue. Repository-controlled
metadata is not an authentication boundary; callers must never use the
identity alone to grant permissive authority.

A workspace with no identity and a workspace whose identity nothing could
settle are different answers and are kept apart here. ``None`` is the first:
the workspace names no conventional clone. ``ProjectIdentityError`` is the
second, and covers both a resident that could not read the workspace and a
resident that was not there to ask. A caller that read the second as the
first would compose policy as if the workspace belonged to no project, which
drops the portable half of a most-restrictive composition.
"""

from __future__ import annotations

import functools
import os
from collections.abc import Mapping
from pathlib import Path
from typing import Any

PORTABLE_PROJECT_IDENTITY_PREFIX = "git-project:v1:"
_MAX_REQUEST_BYTES = 64 * 1024


class ProjectIdentityError(RuntimeError):
    """The resident gave no usable project identity answer."""


def is_portable_project_identity(value: object) -> bool:
    return (
        isinstance(value, str)
        and value.startswith(PORTABLE_PROJECT_IDENTITY_PREFIX)
        and len(value) == len(PORTABLE_PROJECT_IDENTITY_PREFIX) + 64
        and all(character in "0123456789abcdef" for character in value[-64:])
    )


def resolve_portable_project_identity(workspace: str | Path | None, *, guard_home: Path | None = None) -> str | None:
    """Return a stable opaque classification for a conventional Git project.

    The identity is stable across clone locations when the clones share the
    same canonical origin remote and the initial HEAD reflog records that
    origin. Both files are repository-controlled and therefore do not
    authenticate the workspace. The resident reads them directly and never
    launches a subprocess. ``None`` means the workspace names no conventional
    clone; a workspace the resident cannot settle, and a resident that is not
    there to ask, both raise ``ProjectIdentityError`` so the caller can fail
    closed instead of reading the workspace as having no project.
    ``guard_home`` names the store asking the question, so a caller holding a
    home other than the context-bound one is answered by that home's resident
    rather than the default one.

    A workspace named relative to this process is resolved against this
    process's working directory, so the request reports it; the resident
    reads the name under it exactly as the retired
    ``Path(workspace).resolve(strict=False)`` did.
    """
    if isinstance(workspace, Path):
        workspace = str(workspace)
    if not isinstance(workspace, str) or not workspace.strip():
        return None
    from .native_execution import _resident_request
    from .native_resident_decision import ResidentOperation, resident_decide

    operation = ResidentOperation(
        operation="project_identity",
        feature="project-identity-v1",
        prefix="native_project_identity",
        request_schema="guard-project-identity-request.v1",
        result_schema="guard-project-identity-result.v1",
        request_id_prefix="project-identity",
        timeout_seconds=2.0,
        error=ProjectIdentityError,
    )

    def validate(payload: dict[str, Any]) -> None:
        identity = payload.get("identity", False)
        if set(payload) != {"kind", "identity"} or not (identity is None or is_portable_project_identity(identity)):
            raise ProjectIdentityError(operation.invalid)

    query: dict[str, object] = {"kind": "resolve", "workspace": workspace}
    cwd = _process_directory()
    if cwd is not None:
        query["cwd"] = cwd
    payload = resident_decide(
        operation,
        functools.partial(_resident_request, max_request_bytes=_MAX_REQUEST_BYTES),
        query,
        guard_home,
        validate,
    )
    return payload["identity"]


def portable_project_identity_or_none(workspace: str | Path | None, *, guard_home: Path | None = None) -> str | None:
    """The identity, or ``None`` when there is none and when none could be settled.

    Only callers whose use of the identity can only ever widen a match may
    collapse the two answers: metadata enrichment labels a row with the
    project it belongs to, so a row left unlabelled is matched by fewer
    lookups rather than by more.
    """
    try:
        return resolve_portable_project_identity(workspace, guard_home=guard_home)
    except ProjectIdentityError:
        return None


def _process_directory() -> str | None:
    """This process's working directory, or ``None`` when it no longer has one."""
    try:
        return os.getcwd()
    except OSError:
        return None


def resolve_project_identity_from_metadata(
    metadata: Mapping[str, object], *, guard_home: Path | None = None
) -> str | None:
    """Resolve explicit project identity first, upgrading path-like ids when possible."""
    explicit = _first_string(metadata, "project_id", "projectId")
    if explicit and not _looks_like_local_path(explicit):
        return explicit

    workspace = _first_string(metadata, "workspace_path", "workspacePath") or explicit
    portable = portable_project_identity_or_none(workspace, guard_home=guard_home)
    if portable is not None:
        return portable
    return explicit


def enrich_project_identity_metadata(
    metadata: Mapping[str, object], *, guard_home: Path | None = None
) -> dict[str, object]:
    """Return metadata with the canonical project identity in ``project_id``."""
    enriched = {str(key): value for key, value in metadata.items()}
    project_identity = resolve_project_identity_from_metadata(metadata, guard_home=guard_home)
    if project_identity is not None:
        enriched["project_id"] = project_identity
    return enriched


def _first_string(metadata: Mapping[str, object], *keys: str) -> str | None:
    for key in keys:
        value = metadata.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _looks_like_local_path(value: str) -> bool:
    normalized = value.strip()
    if normalized.startswith(("/", "~/", "./", "../", "\\\\")):
        return True
    return len(normalized) >= 3 and normalized[1:3] in {":\\", ":/"}
