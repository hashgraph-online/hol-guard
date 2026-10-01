"""Mechanical Python transport for the native approval-context digest op.

The Rust ``context_digest`` resident operation owns the canonical encoding and
hashing behind approval-context tokens and configured environment/header
digests.  This adapter only encodes the typed request, transports it to the
resident, and strictly validates the result — including a request digest the
caller can reproduce — without reimplementing any hashing semantics.
"""

from __future__ import annotations

import hashlib
import json
import threading
import time
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from pathlib import Path
from typing import Any

from .native_resident_client import native_resident_client_request
from .native_response_decoder import native_error as _native_error
from .native_runtime import _isolated_environment, native_runtime_status
from .native_runtime_resilience import (
    native_record_overload,
    native_record_resident_failure,
    native_record_resident_success,
)

_CONTEXT_DIGEST_FEATURE = "context-digest-v1"
_RESIDENT_PROTOCOL_FEATURE = "resident-protocol-v2"
_REQUEST_SCHEMA = "guard-context-digest-request.v1"
_RESULT_SCHEMA = "guard-context-digest-result.v1"
_RESULT_REQUIRED_KEYS = {"schema", "request_id", "request_sha256", "status", "code"}
_RESULT_OPTIONAL_KEYS = {"token", "digest", "validation_reason"}
_RESULT_CODES = {
    "ok",
    "native_context_component_invalid",
    "native_context_values_invalid",
}
_MAX_REQUEST_BYTES = 2 * 1024 * 1024
_TIMEOUT_SECONDS = 0.5

# Enforcement entry points that already resolved a guard home bind it here so
# digest calls share the ambient resident instead of spawning a second one
# under the default home.  Unbound calls fall back to the default resolution.
_BOUND_GUARD_HOME: ContextVar[Path | None] = ContextVar("guard_context_digest_home", default=None)

# ContextVars do not propagate to worker threads (the policy publisher, for
# example, builds observed MCP identities on its own thread).  Remember the
# most recently bound enforcement home at process level so those threads —
# and genuinely unbound callers — reuse the deployment's resident rather than
# resolving the default home.  Digest output is home-independent, so the worst
# case is a second resident spawn, never a different answer.
_LAST_BOUND_LOCK = threading.Lock()
_last_bound_home: Path | None = None

# Digest results are pure functions of (kind, canonical request, guard home):
# identical requests always map to identical tokens/digests.  Enforcement paths
# re-hash the configured environment on every authority rebuild, so cache
# successful results keyed by the request digest and avoid a resident round
# trip per rebuild.  `request_sha256` cannot collide across differing inputs
# without a SHA-256 break, so correctness does not depend on eviction order.
_RESULT_CACHE_LOCK = threading.Lock()
_RESULT_CACHE: dict[tuple[str, str], dict[str, Any]] = {}
_RESULT_CACHE_MAX = 256


def bind_context_digest_home(guard_home: Path | None, *, remember: bool = True) -> Any:
    """Bind the enforcement path's guard home for ambient digest calls."""

    token = _BOUND_GUARD_HOME.set(guard_home)
    if remember and guard_home is not None:
        global _last_bound_home
        with _LAST_BOUND_LOCK:
            _last_bound_home = guard_home
    return token


def reset_context_digest_home(token: Any) -> None:
    _BOUND_GUARD_HOME.reset(token)


def context_digest_guard_home() -> Path | None:
    bound = _BOUND_GUARD_HOME.get()
    if bound is not None:
        return bound
    with _LAST_BOUND_LOCK:
        return _last_bound_home


@contextmanager
def bound_context_digest_home(guard_home: Path | None) -> Iterator[None]:
    """Bind ``guard_home`` for digest calls made inside the ``with`` block."""

    token = bind_context_digest_home(guard_home)
    try:
        yield
    finally:
        reset_context_digest_home(token)


def _canonical_request_sha256(request: dict[str, Any]) -> str:
    """Reproduce the worker's order-independent request digest.

    The worker hashes the canonical (sorted-key, compact, ensure-ascii)
    serialization of the decoded request, so canonicalizing this side's dict
    yields the identical bytes whenever values survive JSON transport
    unchanged.  Divergence (for example integers beyond u64) fails the
    comparison instead of silently producing a different token.
    """

    canonical = json.dumps(
        request,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


# Successful results must carry the output the kind's callers index; an `ok`
# response missing it is an incomplete (and therefore invalid) result.
_OK_OUTPUT_FIELD: dict[str, str] = {
    "build_approval_context_token": "token",
    "configured_environment_hash": "digest",
    "configured_headers_hash": "digest",
    "launch_argv_digest": "digest",
}


def _decode_result(
    payload: object,
    *,
    request_id: str,
    request_sha256: str,
    kind: str,
) -> dict[str, Any] | None:
    if not isinstance(payload, dict):
        return None
    keys = set(payload)
    if not keys.issuperset(_RESULT_REQUIRED_KEYS) or not keys.issubset(_RESULT_REQUIRED_KEYS | _RESULT_OPTIONAL_KEYS):
        return None
    if (
        payload.get("schema") != _RESULT_SCHEMA
        or payload.get("request_id") != request_id
        or payload.get("request_sha256") != request_sha256
        or payload.get("status") not in {"ok", "error"}
        or payload.get("code") not in _RESULT_CODES
        or (payload.get("status") == "ok" and payload.get("code") != "ok")
        or (payload.get("status") == "error" and payload.get("code") == "ok")
    ):
        return None
    for field in _RESULT_OPTIONAL_KEYS:
        value = payload.get(field)
        if value is not None and not isinstance(value, str):
            return None
    required_output = _OK_OUTPUT_FIELD.get(kind)
    if required_output is not None and payload.get("status") == "ok" and not payload.get(required_output):
        return None
    return payload


def native_context_digest(
    kind: str,
    kind_fields: dict[str, Any],
    *,
    guard_home: Path,
    timeout_seconds: float = _TIMEOUT_SECONDS,
) -> dict[str, Any] | None:
    """Run one ``context_digest`` sub-operation and return its typed result.

    Returns ``None`` when the native runtime is unavailable, incompatible,
    overloaded, or the result fails strict binding checks.  A returned result
    carries ``status``/``code`` plus the kind-specific output field.
    """

    status = native_runtime_status()
    if (
        status.mode == "off"
        or not status.available
        or not status.compatible
        or status.identity is None
        or status.capabilities is None
        or _CONTEXT_DIGEST_FEATURE not in status.capabilities.features
        or _RESIDENT_PROTOCOL_FEATURE not in status.capabilities.features
        or timeout_seconds <= 0
    ):
        return None
    deadline_started = time.monotonic()
    deadline_monotonic = deadline_started + min(timeout_seconds, 1.0)
    deadline_budget_ms = max(1, min(9_000, int(timeout_seconds * 1_000)))
    request_id = uuid.uuid4().hex
    request: dict[str, Any] = {
        "schema": _REQUEST_SCHEMA,
        "request_id": request_id,
        "kind": kind,
        **kind_fields,
    }
    try:
        request_sha256 = _canonical_request_sha256(request)
        # Cache on the request *content* — `request_id` is random per call, so
        # it is excluded from the canonical material.
        content_sha256 = _canonical_request_sha256({"kind": kind, **kind_fields})
    except (TypeError, ValueError):
        # Components the canonical encoder cannot express (non-JSON values,
        # non-finite floats) would fail inside the worker anyway; surface the
        # same failure boundary without shipping the request.
        return None
    cache_key = (content_sha256, str(guard_home))
    with _RESULT_CACHE_LOCK:
        cached = _RESULT_CACHE.get(cache_key)
    if cached is not None:
        return cached
    try:
        envelope = json.dumps(
            {"operation": "context_digest", "deadline_budget_ms": deadline_budget_ms, "request": request},
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (UnicodeEncodeError, ValueError, TypeError):
        # Components carrying lone surrogates (surrogateescape paths/argv on
        # POSIX) cannot cross a strict JSON transport; the legacy ASCII-escaped
        # encoder hashed them.  Report a locally synthesized typed rejection —
        # bound to this request — rather than an availability failure, so
        # callers see the legacy input boundary instead of a crash or a retry
        # storm against a resident that could never accept the payload.
        return {
            "schema": _RESULT_SCHEMA,
            "request_id": request_id,
            "request_sha256": request_sha256,
            "status": "error",
            "code": "native_context_component_invalid",
        }
    if len(envelope) > _MAX_REQUEST_BYTES:
        return None
    output = native_resident_client_request(
        executable=status.identity.path,
        guard_home=guard_home,
        environment=_isolated_environment(),
        payload=envelope,
        deadline_monotonic=deadline_monotonic,
    )
    if output is None:
        native_record_resident_failure(
            status.identity.sha256,
            guard_home,
            reason="native_context_digest_resident_unavailable",
        )
        return None
    try:
        payload = json.loads(output)
    except (UnicodeDecodeError, json.JSONDecodeError):
        payload = None
    if _native_error(payload) == "native_overloaded":
        native_record_overload(status.identity.sha256, guard_home)
        return None
    decoded = _decode_result(payload, request_id=request_id, request_sha256=request_sha256, kind=kind)
    if decoded is None:
        native_record_resident_failure(
            status.identity.sha256,
            guard_home,
            reason="native_context_digest_result_invalid",
        )
        return None
    native_record_resident_success(status.identity.sha256, guard_home)
    if decoded.get("status") == "ok":
        with _RESULT_CACHE_LOCK:
            if len(_RESULT_CACHE) >= _RESULT_CACHE_MAX:
                _RESULT_CACHE.pop(next(iter(_RESULT_CACHE)))
            _RESULT_CACHE[cache_key] = decoded
    return decoded


__all__ = [
    "bind_context_digest_home",
    "bound_context_digest_home",
    "context_digest_guard_home",
    "native_context_digest",
    "reset_context_digest_home",
]
