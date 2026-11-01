"""Canonical request context from the native runtime.

The resident admits a request (owner, remaining budget, policy generation) and
builds its authoritative context in one round trip: the shell working
directory model with symlink and descriptor identities, the runtime launch
identity, and the canonical context digest. Python sends claims and presents
the answer. A hash, identity or "complete" bit that Python computed itself is
never execution authority; an unavailable, malformed or unbound reply is a
``NativeRequestContextFailure`` and callers must fail closed.
"""

from __future__ import annotations

import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal
from uuid import uuid4

from .native_context import (
    _canonical_request_sha256,
    _resolve_digest_home,
    ensure_resident_prerequisite,
)
from .native_execution import _resident_request
from .native_resident_prerequisite_reason import prerequisite_unavailable_code

REQUEST_CONTEXT_FEATURE = "request-context-v1"
_REQUEST_SCHEMA = "guard-request-context-request.v1"
_RESULT_SCHEMA = "guard-request-context-result.v1"
_RESIDENT_CODE = re.compile(r"^native_(?:request_context|sensitive_request)_[a-z_]{1,64}$")
_UNAVAILABLE = "native_request_context_unavailable"
_DEFAULT_BUDGET_MS = 9_000
_TIMEOUT_SECONDS = 10.0

RequestContextSource = Literal["hook", "direct_command", "guard_run", "package", "mcp"]


@dataclass(frozen=True, slots=True)
class NativeRequestContextFailure:
    """No authoritative answer; ``code`` says why, for diagnostics only."""

    code: str


def _owner_uid() -> int | None:
    return None if sys.platform == "win32" else os.geteuid()


def _absolute_text(path: Path | str | None) -> str | None:
    """Anchor a relative path to this process: the resident's cwd is unrelated."""

    return None if path is None else str(Path(path).absolute())


def _call(
    action: dict[str, Any],
    *,
    source: RequestContextSource,
    guard_home: Path | None,
    budget_ms: int,
) -> dict[str, Any] | NativeRequestContextFailure:
    home = _resolve_digest_home(guard_home)
    request: dict[str, Any] = {
        "schema": _REQUEST_SCHEMA,
        "request_id": f"request-context-{uuid4().hex}",
        "guard_home": str(home),
        "source": source,
        "budget_ms": budget_ms,
        "owner_uid": _owner_uid(),
        "action": action,
    }
    try:
        digest = "sha256:" + _canonical_request_sha256(request)
    except (TypeError, ValueError):
        return NativeRequestContextFailure("native_request_context_request_invalid")
    if not ensure_resident_prerequisite(home):
        return NativeRequestContextFailure(
            prerequisite_unavailable_code("native_request_context_prerequisite_unavailable", home)
        )
    response = _resident_request(
        operation="request_context_build",
        request=request,
        guard_home=home,
        timeout_seconds=_TIMEOUT_SECONDS,
        required_feature=REQUEST_CONTEXT_FEATURE,
        response_schema=_RESULT_SCHEMA,
    )
    if (
        response is None
        or response.get("schema") != _RESULT_SCHEMA
        or response.get("request_id") != request["request_id"]
        or response.get("request_sha256") != digest
    ):
        return NativeRequestContextFailure(_UNAVAILABLE)
    status, code = response.get("status"), response.get("code")
    if status == "error":
        reason = code if isinstance(code, str) and _RESIDENT_CODE.fullmatch(code) else _UNAVAILABLE
        return NativeRequestContextFailure(reason)
    payload = response.get("payload")
    if status != "ok" or code != "ok" or not isinstance(payload, dict):
        return NativeRequestContextFailure("native_request_context_payload_invalid")
    return payload


__all__ = [
    "REQUEST_CONTEXT_FEATURE",
    "NativeRequestContextFailure",
    "RequestContextSource",
]
