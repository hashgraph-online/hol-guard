"""Typed client for the native skill workflow-preflight owner; no Python evaluator.

Rust owns both halves of the advisory workflow requirements: reading a skill's
``hol-guard.dependencies`` manifest, and planning that declaration against the
saved local-CLI authority. Python only frames what it read -- the manifest text
for the first, the declaration document and the store rows for the second --
binds the answer by ``request_id`` and canonical ``request_sha256``, and hands
the document back unchanged.

Nothing here re-reads a manifest or works a requirement out for itself. Any
transport, capability, or binding failure raises
``NativeSkillWorkflowPreflightError``; a failure is never an empty declaration
and never a plan with no requirements, both of which would read as "nothing to
review".
"""

from __future__ import annotations

import uuid
from pathlib import Path
from typing import Any

from .native_context import (
    _native_runtime_status_memo,
)
from .native_resident_decision import BoundCall, bound_resident_call
from .runtime.json_safe_copy import json_safe_copy

_FEATURE = "skill-workflow-preflight-v1"
_REQUEST_SCHEMA = "guard-skill-workflow-preflight-request.v1"
_RESULT_SCHEMA = "guard-skill-workflow-preflight-result.v1"
_MAX_REQUEST_BYTES = 2 * 1024 * 1024
_TIMEOUT_SECONDS = 5.0


class NativeSkillWorkflowPreflightError(ValueError):
    """The native owner could not supply a bound workflow-preflight document.

    A ``ValueError`` so an indexing caller already recording per-skill issues
    records this one too, instead of indexing the skill with no declaration.
    """


_CALL = BoundCall(
    operation="skill_workflow_preflight",
    feature=_FEATURE,
    prefix="native_skill_workflow_preflight",
    result_schema=_RESULT_SCHEMA,
    max_request_bytes=_MAX_REQUEST_BYTES,
    timeout_seconds=_TIMEOUT_SECONDS,
    error=NativeSkillWorkflowPreflightError,
    sha_prefix="sha256:",
    bound_canonical=True,
    clock_after_prerequisite=True,
)


def _request(subop: str, dependencies: object, preflight: object) -> dict[str, Any]:
    return {
        "schema": _REQUEST_SCHEMA,
        "request_id": uuid.uuid4().hex,
        "subop": subop,
        "dependencies": dependencies,
        "preflight": preflight,
    }


def _round_trip(request: dict[str, Any], guard_home: Path | None) -> dict[str, object]:
    """One bound resident round trip; returns the verified ``payload`` document."""
    reply = bound_resident_call(_CALL, request, guard_home=guard_home, status=_native_runtime_status_memo())
    return reply.payload()


def _manifest_text(frontmatter: dict[str, object]) -> tuple[bool, str | None]:
    """Transport shaping only: was a manifest declared, and can it reach Rust?

    A declared value that is not text, or is text Guard cannot put on the wire,
    has no manifest for the resident to read -- which is the same ``invalid``
    verdict the resident reaches for text it cannot parse.
    """
    metadata = frontmatter.get("metadata") if isinstance(frontmatter, dict) else None
    raw = metadata.get("hol-guard.dependencies") if isinstance(metadata, dict) else None
    if raw is None:
        return False, None
    if not isinstance(raw, str):
        return True, None
    try:
        raw.encode()
    except UnicodeError:
        return True, None
    return True, raw


def native_skill_dependencies(
    frontmatter: dict[str, object],
    guard_home: Path | None = None,
) -> dict[str, object]:
    """Read a skill's declared tool dependencies in the resident."""
    present, text = _manifest_text(frontmatter)
    request = _request("dependencies", {"present": present, "text": text}, None)
    return _round_trip(request, guard_home)


def native_skill_preflight(
    dependencies: dict[str, object],
    items: list[dict[str, object]],
    *,
    revision: int,
    guard_home: Path | None = None,
) -> dict[str, object]:
    """Plan a declaration against the saved local-CLI authority in the resident."""
    request = _request(
        "preflight",
        None,
        {
            "dependencies": json_safe_copy(dependencies),
            "connections": [json_safe_copy(item) for item in items],
            "authority_revision": revision,
        },
    )
    return _round_trip(request, guard_home)
