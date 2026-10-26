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

import json
import time
import uuid
from pathlib import Path
from typing import Any

from .native_context import (
    _canonical_request_sha256,
    _native_error,
    _native_runtime_status_memo,
    _resolve_digest_home,
    ensure_resident_prerequisite,
)
from .native_resident_client import native_resident_client_request
from .native_resident_prerequisite_reason import prerequisite_unavailable_code
from .native_runtime import _isolated_environment
from .native_runtime_resilience import (
    native_record_overload,
    native_record_resident_failure,
    native_record_resident_success,
)
from .runtime.json_safe_copy import json_safe_copy

_FEATURE = "skill-workflow-preflight-v1"
_RESIDENT_PROTOCOL_FEATURE = "resident-protocol-v2"
_REQUEST_SCHEMA = "guard-skill-workflow-preflight-request.v1"
_RESULT_SCHEMA = "guard-skill-workflow-preflight-result.v1"
_MAX_REQUEST_BYTES = 2 * 1024 * 1024
_TIMEOUT_SECONDS = 5.0
_INVALID_RESULT = "native_skill_workflow_preflight_result_invalid"


class NativeSkillWorkflowPreflightError(ValueError):
    """The native owner could not supply a bound workflow-preflight document.

    A ``ValueError`` so an indexing caller already recording per-skill issues
    records this one too, instead of indexing the skill with no declaration.
    """


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
    guard_home = _resolve_digest_home(guard_home)
    status = _native_runtime_status_memo()
    if (
        not status.available
        or not status.compatible
        or status.identity is None
        or status.capabilities is None
        or _FEATURE not in status.capabilities.features
        or _RESIDENT_PROTOCOL_FEATURE not in status.capabilities.features
    ):
        raise NativeSkillWorkflowPreflightError("native_skill_workflow_preflight_unavailable")
    try:
        prerequisite = ensure_resident_prerequisite(guard_home)
    except Exception as error:
        raise NativeSkillWorkflowPreflightError("native_skill_workflow_preflight_prerequisite_unavailable") from error
    if not prerequisite:
        raise NativeSkillWorkflowPreflightError(
            prerequisite_unavailable_code("native_skill_workflow_preflight_prerequisite_unavailable", guard_home)
        )
    try:
        request_sha256 = "sha256:" + _canonical_request_sha256(request)
        # Rust bounds the ASCII-escaped canonical form, which can exceed the
        # UTF-8 envelope for non-ASCII text; reject on whichever is larger.
        canonical_size = len(
            json.dumps(request, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)
        )
        envelope = json.dumps(
            {"operation": "skill_workflow_preflight", "deadline_budget_ms": 5_000, "request": request},
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        raise NativeSkillWorkflowPreflightError("native_skill_workflow_preflight_component_unencodable") from error
    if max(len(envelope), canonical_size) > _MAX_REQUEST_BYTES:
        raise NativeSkillWorkflowPreflightError("native_skill_workflow_preflight_request_too_large")
    try:
        output = native_resident_client_request(
            executable=status.identity.path,
            guard_home=guard_home,
            environment=_isolated_environment(),
            payload=envelope,
            deadline_monotonic=time.monotonic() + _TIMEOUT_SECONDS,
        )
    except Exception:
        # RuntimeError (thread start), OSError, timeouts: all one typed failure.
        output = None
    if output is None:
        native_record_resident_failure(
            status.identity.sha256, guard_home, reason="native_skill_workflow_preflight_resident_unavailable"
        )
        raise NativeSkillWorkflowPreflightError("native_skill_workflow_preflight_resident_unavailable")
    try:
        result = json.loads(output)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        native_record_resident_failure(status.identity.sha256, guard_home, reason=_INVALID_RESULT)
        raise NativeSkillWorkflowPreflightError(_INVALID_RESULT) from error
    error_code = _native_error(result)
    if error_code is not None:
        if error_code == "native_overloaded":
            native_record_overload(status.identity.sha256, guard_home)
        else:
            native_record_resident_failure(status.identity.sha256, guard_home, reason=error_code)
        raise NativeSkillWorkflowPreflightError(error_code)
    if (
        not isinstance(result, dict)
        or result.get("schema") != _RESULT_SCHEMA
        or result.get("request_id") != request["request_id"]
        or result.get("request_sha256") != request_sha256
        or result.get("status") != "ok"
        or result.get("code") != "ok"
        or not isinstance(result.get("payload"), dict)
    ):
        native_record_resident_failure(status.identity.sha256, guard_home, reason=_INVALID_RESULT)
        code = result.get("code") if isinstance(result, dict) else None
        raise NativeSkillWorkflowPreflightError(
            code if isinstance(code, str) and code.startswith("native_skill_workflow_preflight_") else _INVALID_RESULT
        )
    native_record_resident_success(status.identity.sha256, guard_home)
    return result["payload"]


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
