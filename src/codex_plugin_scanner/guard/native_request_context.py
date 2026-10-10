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
from collections.abc import Mapping, Sequence
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

REQUEST_CONTEXT_FEATURE = "request-context-v1"
_REQUEST_SCHEMA = "guard-request-context-request.v1"
_RESULT_SCHEMA = "guard-request-context-result.v1"
_CONTEXT_SCHEMA = "guard-request-context.v1"
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_RESIDENT_CODE = re.compile(r"^native_request_context_[a-z_]{1,64}$")
_UNAVAILABLE = "native_request_context_unavailable"
_DEFAULT_BUDGET_MS = 9_000
_TIMEOUT_SECONDS = 10.0

RequestContextSource = Literal["hook", "direct_command", "guard_run", "package", "mcp"]


@dataclass(frozen=True, slots=True)
class NativeRequestContext:
    """Resident-derived context; ``shell`` is the raw wire shell report."""

    context_sha256: str
    admission: Mapping[str, Any]
    shell: Mapping[str, Any] | None
    launch: Mapping[str, Any] | None
    target: str | None


@dataclass(frozen=True, slots=True)
class NativeRequestContextFailure:
    """No authoritative answer; ``code`` says why, for diagnostics only."""

    code: str


def request_context_guard_home(guard_home: Path | None = None) -> Path:
    """Resolve the resident home the same way the digest transport does."""

    return _resolve_digest_home(guard_home)


def _owner_uid() -> int | None:
    return None if sys.platform == "win32" else os.geteuid()


def _absolute_text(path: Path | str | None) -> str | None:
    """Anchor a relative path to this process: the resident's cwd is unrelated."""

    return None if path is None else str(Path(path).absolute())


_EXECUTABLE_DEFAULTS: Mapping[str, Any] = {
    "command": None,
    "args": (),
    "structured_command": False,
    "direct_executable": False,
    "search_path": None,
    "launch_env": None,
}


def _executable_wire(executable: Mapping[str, Any] | None) -> dict[str, Any] | None:
    """Spell out every field the resident defaults.

    The request digest is taken over the typed request the resident decodes, so
    omitted optional fields come back as their defaults and must be sent that
    way or the reply would not bind to what Python hashed.
    """

    if executable is None:
        return None
    return {
        **{key: list(value) if key == "args" else value for key, value in _EXECUTABLE_DEFAULTS.items()},
        **executable,
    }


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
        return NativeRequestContextFailure("native_request_context_prerequisite_unavailable")
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


def native_request_context_build(
    *,
    source: RequestContextSource,
    guard_home: Path | None = None,
    budget_ms: int = _DEFAULT_BUDGET_MS,
    script: str | None = None,
    cwd: Path | str | None = None,
    workspace: Path | str | None = None,
    home_dir: Path | str | None = None,
    target: str | None = None,
    policy: Mapping[str, Any] | None = None,
    executable: Mapping[str, Any] | None = None,
) -> NativeRequestContext | NativeRequestContextFailure:
    """Admit the request and build its canonical context in one round trip."""

    try:
        body: dict[str, Any] = {
            "policy": dict(policy) if policy is not None else None,
            "workspace": _absolute_text(workspace),
            "cwd": _absolute_text(cwd),
            "fallback_cwd": _absolute_text(_process_cwd()) if cwd is None else None,
            "home_dir": _absolute_text(home_dir),
            "script": script,
            "target": target,
            "executable": _executable_wire(executable),
        }
    except OSError:
        return NativeRequestContextFailure("native_request_context_request_invalid")
    payload = _call({"kind": "build", "body": body}, source=source, guard_home=guard_home, budget_ms=budget_ms)
    if isinstance(payload, NativeRequestContextFailure):
        return payload
    decoded = _decode_build(payload)
    return decoded if decoded is not None else NativeRequestContextFailure("native_request_context_payload_invalid")


def _process_cwd() -> Path | None:
    try:
        return Path.cwd()
    except OSError:
        return None


def native_shell_validate_segment(
    context: Mapping[str, Any],
    segment_index: int,
    *,
    guard_home: Path | None = None,
    budget_ms: int = _DEFAULT_BUDGET_MS,
) -> tuple[str | None, str | None] | NativeRequestContextFailure:
    """Re-read the filesystem for one modeled segment: ``(cwd, reason_code)``."""

    payload = _call(
        {"kind": "validate_segment", "body": {"context": dict(context), "segment_index": segment_index}},
        source="hook",
        guard_home=guard_home,
        budget_ms=budget_ms,
    )
    if isinstance(payload, NativeRequestContextFailure):
        return payload
    cwd, reason = payload.get("effective_cwd"), payload.get("reason_code")
    if (
        set(payload) != {"effective_cwd", "reason_code", "context_hash", "segment_hash"}
        or not (cwd is None or isinstance(cwd, str))
        or not (reason is None or isinstance(reason, str))
        or (cwd is None) == (reason is None)
    ):
        return NativeRequestContextFailure("native_request_context_payload_invalid")
    return cwd, reason


def native_shell_hashes(
    context: Mapping[str, Any],
    segment_index: int | None = None,
    *,
    guard_home: Path | None = None,
    budget_ms: int = _DEFAULT_BUDGET_MS,
) -> tuple[str, str | None, Mapping[str, Any]] | NativeRequestContextFailure:
    """Recompute ``(context_hash, segment_hash, metadata)`` natively."""

    payload = _call(
        {"kind": "hash", "body": {"context": dict(context), "segment_index": segment_index}},
        source="hook",
        guard_home=guard_home,
        budget_ms=budget_ms,
    )
    if isinstance(payload, NativeRequestContextFailure):
        return payload
    context_hash, segment_hash, metadata = (
        payload.get("context_hash"),
        payload.get("segment_hash"),
        payload.get("metadata"),
    )
    if (
        set(payload) != {"context_hash", "segment_hash", "metadata"}
        or not isinstance(context_hash, str)
        or _SHA256.fullmatch(context_hash) is None
        or not (segment_hash is None or (isinstance(segment_hash, str) and _SHA256.fullmatch(segment_hash)))
        or not isinstance(metadata, dict)
    ):
        return NativeRequestContextFailure("native_request_context_payload_invalid")
    return context_hash, segment_hash, metadata


_BUILD_KEYS = frozenset({"schema", "admission", "shell", "launch", "target", "context_sha256"})
_SHELL_KEYS = frozenset({"context", "context_hash", "segment_hashes", "metadata"})


def _decode_build(payload: Mapping[str, Any]) -> NativeRequestContext | None:
    if set(payload) != _BUILD_KEYS or payload["schema"] != _CONTEXT_SCHEMA:
        return None
    digest, admission, shell, launch, target = (
        payload["context_sha256"],
        payload["admission"],
        payload["shell"],
        payload["launch"],
        payload["target"],
    )
    if not isinstance(digest, str) or _SHA256.fullmatch(digest) is None or not isinstance(admission, dict):
        return None
    if shell is not None and (not isinstance(shell, dict) or set(shell) != _SHELL_KEYS):
        return None
    if shell is not None and not _shell_hashes_valid(shell):
        return None
    if launch is not None and not isinstance(launch, dict):
        return None
    if target is not None and not isinstance(target, str):
        return None
    return NativeRequestContext(digest, admission, shell, launch, target)


def _shell_hashes_valid(shell: Mapping[str, Any]) -> bool:
    context_hash = shell["context_hash"]
    segment_hashes = shell["segment_hashes"]
    context = shell["context"]
    if not isinstance(context_hash, str) or _SHA256.fullmatch(context_hash) is None:
        return False
    if not isinstance(context, dict) or not isinstance(shell["metadata"], dict):
        return False
    segments = context.get("segments")
    if not isinstance(segments, Sequence) or not isinstance(segment_hashes, list):
        return False
    return len(segments) == len(segment_hashes) and all(
        isinstance(item, str) and _SHA256.fullmatch(item) is not None for item in segment_hashes
    )


__all__ = [
    "REQUEST_CONTEXT_FEATURE",
    "NativeRequestContext",
    "NativeRequestContextFailure",
    "RequestContextSource",
    "native_request_context_build",
    "native_shell_hashes",
    "native_shell_validate_segment",
    "request_context_guard_home",
]
