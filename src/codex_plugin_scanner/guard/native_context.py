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
import os
import threading
import time
import uuid
from collections import OrderedDict
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from contextvars import ContextVar
from copy import deepcopy
from pathlib import Path
from typing import Any, TypeGuard

from .directory_path_authority import canonical_guard_home_path
from .fork_safety import forget_in_child
from .native_context_budget import (
    bind_context_digest_lifecycle_budget,
    context_digest_timeout_floor,
    reset_context_digest_budget,
)
from .native_resident_client import (
    native_resident_client_failure_code,
    native_resident_client_ready,
    native_resident_client_request,
    native_resident_client_transport,
)
from .native_resident_prerequisite_reason import (
    clear_prerequisite_failure,
    prerequisite_failure_reason,
    prerequisite_unavailable_code,
    record_prerequisite_failure,
)
from .native_response_decoder import native_error as _native_error
from .native_runtime import NativeRuntimeStatus, _isolated_environment, native_runtime_status
from .native_runtime_request_scope import _status_binary_unchanged
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
_RESULT_OPTIONAL_KEYS = {
    "token",
    "digest",
    "validation_reason",
    "package_context",
    "mcp_server_identity",
    "mcp_tool_identity",
    "browser_mcp",
    "mcp_launch_environment",
    "mcp_redacted_value",
    "runtime_identity",
    "runtime_identity_match",
    "runtime_identity_reusable",
    "runtime_resolved_executable",
    "runtime_resolved_argv",
    "tool_catalog",
    "local_cli_identity",
    "custom_extension_continuity",
    "package_json_scripts",
    "local_cli_identities",
    "custom_extension_suggestion",
    "managed_controls_policy_fields",
    "claude_guard_question",
    "memory_pattern",
}
_RESULT_CODES = {
    "ok",
    "native_context_component_invalid",
    "native_context_values_invalid",
    "native_browser_argument_key_duplicated",
    "native_mcp_risk_pattern_failed",
    "native_mcp_risk_serialization_failed",
    "canonical_json_unencodable",
    "native_mcp_arguments_invalid",
    "native_local_cli_identify_deadline",
    "native_local_cli_identify_program_unavailable",
    "native_hook_approval_context_invalid",
    "native_hook_approval_context_path_unresolved",
    "native_hook_approval_context_random_failed",
    "native_custom_extension_continuity_invalid_request",
}

# Filesystem authority: launch/executable identities hash on-disk bytes and
# stat metadata, so the same request legitimately produces a different result
# after entrypoint/executable bytes change; `package_json_scripts` reads the
# project's package.json and lockfiles, and `local_cli_identify` resolves
# launches and runner bins on disk.  `mcp_launch_environment` is also
# uncacheable because it carries granted credentials (see the transport
# comment below).  Every other kind is a pure function of request content.
_UNCACHEABLE_DIGEST_KINDS = frozenset(
    {
        "generic_hook_approval_context",
        "mcp_launch_environment",
        "runtime_executable_identity",
        "runtime_hook_approval_context",
        "runtime_launch_identity",
        "runtime_launch_identity_matches",
        "runtime_launch_identity_projection",
        "package_json_scripts",
        "local_cli_identify",
    }
)
_MAX_REQUEST_BYTES = 2 * 1024 * 1024
_TIMEOUT_SECONDS = 0.5
# Allowance for the pooled resident's lazy spawn, granted whenever the pool has no
# idle client to serve the request.  Steady-state requests keep the tight budget;
# a spawn on a contended runner must not fail closed.
_COLD_START_ALLOWANCE_SECONDS = 3.0
# A digest request is retried once, with the allowance, when the failure is the
# deadline running out: the pooled client serialises requests, so the tight
# steady-state budget can lose the lock to a long sibling RPC, and the resident
# reports its own deadline (`native_client_deadline_exceeded`) when it starts
# serving after the budget the request carried has already lapsed. Both are
# "not enough time", not "this resident is gone".
_DIGEST_ATTEMPTS = 2
_DEADLINE_FAILURE_CODES = frozenset({"native_client_timed_out", "native_client_deadline_exceeded"})
# The retry is the last word on whether the resident is contended or gone, so it
# carries twice the allowance.  Only a request that has already failed pays it:
# the steady-state deadline stays tight, and a resident that is genuinely gone
# has the resilience breaker to stop the cost from repeating.
_RETRY_ALLOWANCE_MULTIPLIER = 2

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
_RESULT_CACHE: OrderedDict[tuple[str, str], dict[str, Any]] = OrderedDict()
_RESULT_CACHE_MAX = 256
# Guard homes whose resident on-disk prerequisite is already established by
# this process.  Provisioning is idempotent but builds a store, so the result
# is remembered; a child process re-establishes it (see `forget_in_child`).
_RESIDENT_PREREQUISITE_LOCK = threading.Lock()
_RESIDENT_PREREQUISITE_HOMES: set[str] = set()

# Why the most recent `native_context_digest` call in this context returned
# `None`.  Digest callers that have no fallback raise a `*_unavailable` error,
# and a bare "unavailable" cannot say whether the runtime was missing, the
# guard home unprovisionable, the request oversized, the resident slow, or its
# answer malformed — which is the difference between a bug and a busy machine.
_LAST_DIGEST_FAILURE: ContextVar[str | None] = ContextVar("guard_context_digest_failure", default=None)


def native_context_failure_reason() -> str | None:
    """Reason the last `native_context_digest` call in this context returned `None`."""

    return _LAST_DIGEST_FAILURE.get()


def _digest_failed(reason: str) -> None:
    _LAST_DIGEST_FAILURE.set(reason)
    return None


def _unavailable(message: str) -> ValueError:
    """Bind a digest-unavailable error to the transport's reason when known."""

    reason = _LAST_DIGEST_FAILURE.get()
    return ValueError(f"{message}:{reason}" if reason else message)


# ``native_runtime_status()`` re-reads and SHA-256-hashes the whole runtime
# binary per call.  Batch digest sites (``environment_material`` hashes one
# value per env var, launch verification re-hashes argv/shebang/search-path)
# would otherwise re-validate the binary once per digest — tens of MB of
# rehashing and per-call resident probes inside a single launch.  Memoize the
# status snapshot for a short window so a burst of digests shares one probe.
# A cached result is only reused while the binary's (size, mtime_ns) still
# matches the memoized identity — a binary replaced inside the TTL is
# re-validated on the next digest rather than served from the stale snapshot.
_STATUS_MEMO_LOCK = threading.Lock()
_STATUS_MEMO_TTL_SECONDS = 0.1
# (timestamp, status, status-callable-identity) — the callable identity lets
# tests monkeypatch ``native_runtime_status`` and always get a fresh probe,
# while a production burst keeps sharing the real probe's snapshot.
_status_memo: tuple[float, NativeRuntimeStatus, object] | None = None


def _native_runtime_status_memo() -> NativeRuntimeStatus:
    global _status_memo
    probe = native_runtime_status
    with _STATUS_MEMO_LOCK:
        if (
            _status_memo is not None
            and _status_memo[2] is probe
            and time.monotonic() - _status_memo[0] < _STATUS_MEMO_TTL_SECONDS
            and _status_binary_unchanged(_status_memo[1])
        ):
            return _status_memo[1]
    status = probe()
    with _STATUS_MEMO_LOCK:
        _status_memo = (time.monotonic(), status, probe)
    return status


forget_in_child(_RESULT_CACHE)
forget_in_child(_RESIDENT_PREREQUISITE_HOMES)


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


def _resolve_digest_home(guard_home: Path | None) -> Path:
    if guard_home is not None:
        return guard_home
    bound = context_digest_guard_home()
    if bound is not None:
        return bound
    from .runtime.approval_context import _context_digest_guard_home

    return _context_digest_guard_home(str(Path.home()))


def _resolve_existing_digest_home(guard_home: Path | None) -> Path:
    """Like :func:`_resolve_digest_home`, but never names a home that is not on disk.

    Pure resident verdicts must not create a guard home, or start a resident
    for one, just to be asked a question; a missing home resolves to the
    context home instead.
    """

    if guard_home is not None and os.path.isdir(guard_home):
        return guard_home
    return _resolve_digest_home(None)


def ensure_resident_prerequisite(guard_home: Path) -> bool:
    """Establish the resident's on-disk prerequisite for ``guard_home``.

    The resident refuses every request until the owner-private verifier key
    exists under the home's runtime state, and it never creates that state
    itself.  Native launch/session callers have always provisioned it before
    their RPC; the plain digest transport never did, because launch and
    executable identities used to be computed in Python.  Now that the
    resident owns them, the transport must establish the same prerequisite or
    every identity request fails closed.

    An existing key file is taken as satisfied without touching the store:
    callers that ship their own key (the test harness seeds one, and every
    production entry point provisions before its first RPC) must not need a
    secret-store master that their guard home was never given.  Returns
    ``False`` when a missing prerequisite cannot be created, which callers
    report as an unavailable runtime rather than a crash.
    """

    try:
        key = str(canonical_guard_home_path(guard_home))
    except OSError:
        key = str(guard_home)
    with _RESIDENT_PREREQUISITE_LOCK:
        if key in _RESIDENT_PREREQUISITE_HOMES:
            return True
    from .native_policy_snapshot_constants import (
        NATIVE_POLICY_VERIFIER_KEY_NAME,
        NATIVE_RUNTIME_STATE_DIRECTORY,
    )

    if os.path.isfile(guard_home / NATIVE_RUNTIME_STATE_DIRECTORY / NATIVE_POLICY_VERIFIER_KEY_NAME):
        with _RESIDENT_PREREQUISITE_LOCK:
            _RESIDENT_PREREQUISITE_HOMES.add(key)
        return True
    phase = "open_store"
    try:
        from .native_policy_snapshot_publisher import provision_native_verifier_key_for_store
        from .store import GuardStore

        # Provisioning the resident key must not prime policy decisions or
        # refresh signed store state on the evaluation hot path.
        store = GuardStore(guard_home, prime_policy_integrity=False)
        phase = "provision_key"
        provision_native_verifier_key_for_store(store)
    except Exception as error:
        # Nothing to fall back to: the resident is the only authority for these
        # digests, so an unprovisionable home is an unavailable runtime. The
        # bounded reason rides on the caller's error code for diagnostics.
        record_prerequisite_failure(key, prerequisite_failure_reason(phase, error))
        return False
    clear_prerequisite_failure(key)
    with _RESIDENT_PREREQUISITE_LOCK:
        _RESIDENT_PREREQUISITE_HOMES.add(key)
    return True


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


def _is_sha256_digest(value: object) -> TypeGuard[str]:
    return isinstance(value, str) and len(value) == 64 and all(character in "0123456789abcdef" for character in value)


_LAST_RESULT_REJECTION: ContextVar[str | None] = ContextVar("_LAST_RESULT_REJECTION", default=None)


def native_context_result_rejection_reason() -> str | None:
    """Which contract clause rejected the last digest result, for failure messages.

    A rejected result is otherwise indistinguishable from a resident that
    answered the wrong request, a frame that is not a response at all, and a
    truncated read; naming the clause is what makes the failure actionable.
    """

    return _LAST_RESULT_REJECTION.get()


def _reject(reason: str) -> None:
    _LAST_RESULT_REJECTION.set(reason)
    return None


def _decode_result(
    payload: object,
    *,
    request_id: str,
    request_sha256: str,
) -> dict[str, Any] | None:
    """Bind a result to the request that produced it.

    Only the requester can check the binding (its own id and request digest),
    so that stays here. Field shapes, vocabularies and kind-specific required
    output are the resident's result contract: it refuses to emit a result
    that breaks them, so a broken one reaches this side as an error envelope.
    """

    if not isinstance(payload, dict):
        return _reject("payload_not_object")
    keys = set(payload)
    if not keys.issuperset(_RESULT_REQUIRED_KEYS) or not keys.issubset(_RESULT_REQUIRED_KEYS | _RESULT_OPTIONAL_KEYS):
        missing = sorted(_RESULT_REQUIRED_KEYS - keys)
        unexpected = sorted(keys - (_RESULT_REQUIRED_KEYS | _RESULT_OPTIONAL_KEYS))[:3]
        reported = payload.get("error")
        suffix = f" error={reported!r}" if isinstance(reported, str) else ""
        return _reject(f"payload_keys_mismatch missing={missing} unexpected={unexpected}{suffix}")
    if (
        payload.get("schema") != _RESULT_SCHEMA
        or payload.get("request_id") != request_id
        or payload.get("request_sha256") != request_sha256
        or payload.get("status") not in {"ok", "error"}
        or payload.get("code") not in _RESULT_CODES
        or (payload.get("status") == "ok" and payload.get("code") != "ok")
        or (payload.get("status") == "error" and payload.get("code") == "ok")
    ):
        return _reject(
            f"payload_header_mismatch schema={payload.get('schema')!r} "
            f"id_matches={payload.get('request_id') == request_id} "
            f"sha_matches={payload.get('request_sha256') == request_sha256} "
            f"status={payload.get('status')!r} code={payload.get('code')!r}"
        )
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

    _LAST_DIGEST_FAILURE.set(None)
    # A lifecycle command's floor only ever lengthens a budget, and never
    # revives a call whose caller disabled it with a non-positive one.
    floor = context_digest_timeout_floor()
    if floor is not None and timeout_seconds > 0:
        timeout_seconds = max(timeout_seconds, floor)
    status = _native_runtime_status_memo()
    if (
        not status.available
        or not status.compatible
        or status.identity is None
        or status.capabilities is None
        or _CONTEXT_DIGEST_FEATURE not in status.capabilities.features
        or _RESIDENT_PROTOCOL_FEATURE not in status.capabilities.features
        or timeout_seconds <= 0
    ):
        return _digest_failed("native_context_digest_unsupported")
    if not ensure_resident_prerequisite(guard_home):
        return _digest_failed(
            prerequisite_unavailable_code("native_context_digest_prerequisite_unavailable", guard_home)
        )
    canonical_home = canonical_guard_home_path(guard_home)
    # The pool spawns its resident lazily and drops it when the process dies,
    # so ask it rather than remembering: a pair that has answered before can
    # still be asked to pay for a spawn, and one that has not may have a warm
    # client another caller already started.
    environment = _isolated_environment()
    cold_start = not native_resident_client_ready(status.identity.path, guard_home)
    # The budget bounds steady-state degradation, not process startup: the
    # pooled resident is spawned lazily on the first request, and a contended
    # runner can spend several hundred milliseconds faulting a 20 MB binary in
    # before it answers.  Grant that one spawn an allowance so a slow cold
    # start degrades to a slow request instead of a resident-unavailable
    # failure for every caller that has no fallback.
    budget_seconds = timeout_seconds + (_COLD_START_ALLOWANCE_SECONDS if cold_start else 0.0)
    # The resident's own bound is the retry's.  It is the budget the resident may
    # spend on the request, and a retry must not inherit the tight steady-state
    # budget the first attempt carried: a contended resident that starts serving
    # after that deadline answers `native_client_deadline_exceeded`, and it would
    # answer exactly that again.  The client's deadline is what keeps the steady
    # state cheap.
    retry_budget_seconds = timeout_seconds + _RETRY_ALLOWANCE_MULTIPLIER * _COLD_START_ALLOWANCE_SECONDS
    resident_budget_ms = max(1, min(9_000, int(retry_budget_seconds * 1_000)))
    deadline_monotonic = time.monotonic() + budget_seconds
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
        content_sha256 = (
            _canonical_request_sha256({"kind": kind, **kind_fields}) if kind not in _UNCACHEABLE_DIGEST_KINDS else None
        )
    except (TypeError, ValueError):
        # Components the canonical encoder cannot express (non-JSON values,
        # non-finite floats) would fail inside the worker anyway; surface the
        # same failure boundary without shipping the request.
        return _digest_failed("native_context_digest_component_unencodable")
    # Canonicalize (including symlinks) so the same home spelled differently
    # cannot duplicate entries.  Path canonicalization is directory-path
    # authority, not transport work.
    # Launch environments contain granted credentials: do not retain them in
    # the digest result cache or hash the input a second time for caching.
    cache_key = (content_sha256, canonical_home) if content_sha256 is not None else None
    cached = None
    if cache_key is not None:
        with _RESULT_CACHE_LOCK:
            cached = _RESULT_CACHE.get(cache_key)
            if cached is not None:
                _RESULT_CACHE.move_to_end(cache_key)
    if cached is not None:
        # Payload outputs are pure functions of the request content, but the
        # result envelope must be bound to this caller's request — rebind the
        # identity fields rather than returning the original request's.
        return {**deepcopy(cached), "request_id": request_id, "request_sha256": request_sha256}
    try:
        envelope = json.dumps(
            {"operation": "context_digest", "deadline_budget_ms": resident_budget_ms, "request": request},
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
        return _digest_failed("native_context_digest_request_too_large")
    output = None
    attempts = 0
    while attempts < _DIGEST_ATTEMPTS:
        attempts += 1
        output = native_resident_client_request(
            executable=status.identity.path,
            guard_home=guard_home,
            environment=environment,
            payload=envelope,
            deadline_monotonic=deadline_monotonic,
        )
        if output is not None or native_resident_client_failure_code() not in _DEADLINE_FAILURE_CODES:
            break
        # Retry even when the first attempt already carried the allowance: on a
        # contended runner the allowance covers a spawn that has not finished
        # and a lock queue behind a sibling's RPC, and the second attempt finds
        # the process resident and the binary in page cache.  "More time will
        # not help" is true only of a resident that is gone, which the failure
        # code distinguishes after the retry.
        budget_seconds = retry_budget_seconds
        deadline_monotonic = time.monotonic() + budget_seconds
    if output is None:
        # The client's own code ("native_client_timed_out",
        # "native_client_pool_exhausted", ...) is the actionable half of this.
        _digest_failed(
            f"{native_resident_client_failure_code() or 'native_context_digest_resident_unavailable'}"
            f"[{native_resident_client_transport()},{attempts} attempt(s),"
            f"allowance={'granted' if cold_start else 'none'},budget={budget_seconds:.2f}s]"
        )
        native_record_resident_failure(
            status.identity.sha256,
            guard_home,
            reason="native_context_digest_resident_unavailable",
        )
        return None
    try:
        payload = json.loads(output)
    except (UnicodeDecodeError, json.JSONDecodeError):
        native_record_resident_failure(
            status.identity.sha256,
            guard_home,
            reason="native_context_digest_result_invalid",
        )
        return _digest_failed(f"native_context_digest_result_invalid:response_not_json bytes={len(output)}")
    error_code = _native_error(payload)
    if error_code is not None:
        # A resident that answers with its own error envelope is not an invalid
        # result: it is a request the resident refused, and its code is both the
        # actionable reason and the right thing to record against the breaker.
        if error_code == "native_overloaded":
            native_record_overload(status.identity.sha256, guard_home)
            return _digest_failed("native_overloaded")
        native_record_resident_failure(status.identity.sha256, guard_home, reason=error_code)
        return _digest_failed(error_code)
    # A rejection is only meaningful for the result that produced it.
    _LAST_RESULT_REJECTION.set(None)
    decoded = _decode_result(payload, request_id=request_id, request_sha256=request_sha256)
    if decoded is None:
        native_record_resident_failure(
            status.identity.sha256,
            guard_home,
            reason="native_context_digest_result_invalid",
        )
        return _digest_failed(
            f"native_context_digest_result_invalid:{native_context_result_rejection_reason() or 'unknown'}"
        )
    native_record_resident_success(status.identity.sha256, guard_home)
    if decoded.get("status") == "ok" and cache_key is not None:
        with _RESULT_CACHE_LOCK:
            if len(_RESULT_CACHE) >= _RESULT_CACHE_MAX:
                _RESULT_CACHE.popitem(last=False)
            _RESULT_CACHE[cache_key] = deepcopy(decoded)
    return decoded


_UNBOUND_PREFIX = "guard-context-unbound:"


def is_unbound_context_digest(value: object) -> bool:
    """``True`` for degraded digests emitted when the resident is unavailable."""
    return isinstance(value, str) and value.startswith(_UNBOUND_PREFIX)


def _unbound_material_digest(material: object) -> str:
    # Integrity digest over guard material (env values / launch identity / PATH), not a
    # password hash — parity-pinned to the pre-migration hashlib baseline for byte-identical
    # persisted approval rows. codeql[py/weak-sensitive-data-hashing] false positive.
    return hashlib.sha256(_canonical_material_bytes(material)).hexdigest()  # codeql[py/weak-sensitive-data-hashing]


def _canonical_material_bytes(material: object) -> bytes:
    return json.dumps(
        material,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        default=str,
    ).encode("utf-8")


def context_sha256_digest(
    material: object,
    *,
    prefix: str | None = None,
    guard_home: Path | None = None,
    unbound_label: str = "canonical-sha256",
) -> str:
    """Canonical-JSON SHA-256 via the resident op.

    The resident owns the digest.  Without one, this returns a
    ``guard-context-unbound:`` value that fails every equality and validation
    check against a worker-issued digest, so an absent resident can never pass
    for a bound one.
    """

    home = _resolve_digest_home(guard_home)
    result = native_context_digest(
        "canonical_sha256",
        {"material": material, "prefix": prefix},
        guard_home=home,
    )
    digest = result.get("digest") if isinstance(result, dict) else None
    if isinstance(digest, str) and digest:
        return digest
    return f"{_UNBOUND_PREFIX}{unbound_label}:{_unbound_material_digest(material)}"


def context_mcp_launch_environment(
    inherited: Mapping[str, str],
    configured: Mapping[str, str],
    *,
    guard_home: Path | None = None,
) -> dict[str, str]:
    """Transport native MCP child environment selection; no fallback."""
    result = native_context_digest(
        "mcp_launch_environment",
        {"inherited": dict(inherited), "configured": dict(configured)},
        guard_home=_resolve_digest_home(guard_home),
    )
    values = result.get("mcp_launch_environment") if isinstance(result, dict) else None
    if not isinstance(result, dict) or result.get("status") != "ok" or not isinstance(values, dict):
        raise _unavailable("native_mcp_launch_environment_unavailable")
    return values


def _ambient_launch_environment(launch_env: Mapping[str, str] | None) -> dict[str, str]:
    """Mirror `launch_env if launch_env is not None else os.environ`.

    The resident is spawned through `_isolated_environment`, which deliberately
    drops PATH (and every other credential-bearing variable) on POSIX.  A caller
    that supplies no launch environment would therefore lose the ambient PATH
    and every interpreter/module entrypoint would resolve as `unresolved` —
    the in-process reference implementation read `os.environ` here.  Forward the
    ambient environment so the native decision sees exactly what Python saw.
    """

    return dict(launch_env) if launch_env is not None else dict(os.environ)


def context_runtime_executable_identity(
    command: object,
    *,
    search_path: str | None = None,
    cwd: Path | None = None,
    home_dir: Path | None = None,
    require_executable: bool = True,
    guard_home: Path | None = None,
) -> dict[str, Any]:
    """Transport `build_runtime_executable_identity` inputs to native authority; no fallback."""
    result = native_context_digest(
        "runtime_executable_identity",
        {
            "command": command if command is None or isinstance(command, (str, int, float, bool, list, dict)) else None,
            # The in-process reference resolved a bare command with
            # `shutil.which(..., path=search_path or os.environ["PATH"])`; the
            # resident cannot see the ambient PATH, so fall back here.
            "search_path": search_path if search_path is not None else os.environ.get("PATH"),
            "cwd": str(cwd) if cwd is not None else None,
            "home_dir": str(home_dir) if home_dir is not None else None,
            "require_executable": require_executable,
        },
        guard_home=_resolve_digest_home(guard_home),
    )
    identity = result.get("runtime_identity") if isinstance(result, dict) else None
    if not isinstance(result, dict) or result.get("status") != "ok" or not isinstance(identity, dict):
        raise _unavailable("native_runtime_executable_identity_unavailable")
    return identity


def context_runtime_launch_identity(
    command: object,
    *,
    args: Sequence[object] = (),
    structured_command: bool = False,
    direct_executable: bool = False,
    search_path: str | None = None,
    cwd: Path | None = None,
    home_dir: Path | None = None,
    launch_env: Mapping[str, str] | None = None,
    guard_home: Path | None = None,
) -> dict[str, Any]:
    """Transport `build_runtime_launch_identity` inputs to native authority; no fallback."""
    result = native_context_digest(
        "runtime_launch_identity",
        {
            "command": command if command is None or isinstance(command, (str, int, float, bool, list, dict)) else None,
            "args": list(args),
            "structured_command": structured_command,
            "direct_executable": direct_executable,
            "search_path": search_path,
            "cwd": str(cwd) if cwd is not None else None,
            "home_dir": str(home_dir) if home_dir is not None else None,
            "launch_env": _ambient_launch_environment(launch_env),
        },
        guard_home=_resolve_digest_home(guard_home),
    )
    identity = result.get("runtime_identity") if isinstance(result, dict) else None
    if not isinstance(result, dict) or result.get("status") != "ok" or not isinstance(identity, dict):
        raise _unavailable("native_runtime_launch_identity_unavailable")
    return identity


def context_runtime_launch_identity_matches(
    expected_identity: Mapping[str, object],
    command: object,
    *,
    args: Sequence[object] = (),
    structured_command: bool = False,
    direct_executable: bool = False,
    search_path: str | None = None,
    cwd: Path | None = None,
    launch_env: Mapping[str, str] | None = None,
    guard_home: Path | None = None,
) -> bool:
    """`runtime_launch_identity_matches` — rebuild current identity natively and compare."""
    result = native_context_digest(
        "runtime_launch_identity_matches",
        {
            "expected_identity": dict(expected_identity),
            "command": command if command is None or isinstance(command, (str, int, float, bool, list, dict)) else None,
            "args": list(args),
            "structured_command": structured_command,
            "direct_executable": direct_executable,
            "search_path": search_path,
            "cwd": str(cwd) if cwd is not None else None,
            "launch_env": _ambient_launch_environment(launch_env),
        },
        guard_home=_resolve_digest_home(guard_home),
    )
    verdict = result.get("runtime_identity_match") if isinstance(result, dict) else None
    if not isinstance(result, dict) or result.get("status") != "ok" or not isinstance(verdict, bool):
        raise _unavailable("native_runtime_launch_identity_matches_unavailable")
    return verdict


def context_runtime_launch_identity_projection(
    identity: Mapping[str, object],
    *,
    args: Sequence[str] = (),
    guard_home: Path | None = None,
) -> tuple[bool, str | None, tuple[str, ...] | None]:
    """Reusable/resolved-executable/resolved-argv for a stored identity — no fallback."""
    result = native_context_digest(
        "runtime_launch_identity_projection",
        {
            "identity": dict(identity),
            "args": list(args),
        },
        guard_home=_resolve_digest_home(guard_home),
    )
    if not isinstance(result, dict) or result.get("status") != "ok" or "runtime_resolved_argv" not in result:
        raise _unavailable("native_runtime_launch_identity_projection_unavailable")
    reusable = result.get("runtime_identity_reusable")
    executable = result.get("runtime_resolved_executable")
    argv = result.get("runtime_resolved_argv")
    if not isinstance(reusable, bool) or (executable is not None and not isinstance(executable, str)):
        raise _unavailable("native_runtime_launch_identity_projection_unavailable")
    resolved_argv: tuple[str, ...] | None = None
    if argv is not None:
        if not isinstance(argv, list) or not all(isinstance(part, str) for part in argv):
            raise _unavailable("native_runtime_launch_identity_projection_unavailable")
        resolved_argv = tuple(argv)
    return reusable, executable, resolved_argv


def context_mcp_tool_catalog_fingerprint(
    entries: Sequence[tuple[str, Mapping[str, object]]] | Mapping[str, Mapping[str, object]],
    *,
    state: str,
    version: str = "mcp-advertised-tool-catalog-v2",
    guard_home: Path | None = None,
) -> tuple[str | None, dict[str, dict[str, object]] | None]:
    """Canonical tools/list fingerprint + normalized page — no fallback.

    ``entries`` accepts either a ``name → definition`` mapping or a sequence
    of ``(name, definition)`` pairs; the latter preserves duplicate names so
    the native validator can reject them the same way the raw ``tools`` page
    boundary does. Returns ``(fingerprint, page)``: ``fingerprint`` is ``None``
    when the canonical document can't be serialized (Python ``json.dumps``
    ``allow_nan=False`` raises; ``None`` mirrors that failure) and ``page`` is
    ``None`` for any malformed payload (mirrors
    ``_normalized_tools_catalog_page``).
    """
    if isinstance(entries, Mapping):
        wire_entries = [[name, definition] for name, definition in entries.items()]
    else:
        wire_entries = [[name, dict(definition)] for name, definition in entries]
    result = native_context_digest(
        "mcp_tool_catalog_fingerprint",
        {"entries": wire_entries, "state": state, "version": version},
        guard_home=_resolve_digest_home(guard_home),
    )
    if not isinstance(result, dict) or result.get("status") != "ok":
        raise _unavailable("native_mcp_tool_catalog_fingerprint_unavailable")
    digest = result.get("digest")
    page = result.get("tool_catalog")
    if digest is not None and (not isinstance(digest, str) or not digest):
        raise _unavailable("native_mcp_tool_catalog_fingerprint_unavailable")
    if page is not None and not isinstance(page, dict):
        raise _unavailable("native_mcp_tool_catalog_fingerprint_unavailable")
    return digest, page


def context_package_evidence(
    material: object,
    *,
    scanner_evidence: bool = False,
    guard_home: Path | None = None,
) -> dict[str, Any] | None:
    """Transport persisted evidence to native validation and digest authority."""

    result = native_context_digest(
        "package_execution_context_from_scanner_evidence"
        if scanner_evidence
        else "package_execution_context_from_evidence",
        {"material": material},
        guard_home=_resolve_digest_home(guard_home),
    )
    context = result.get("package_context") if isinstance(result, dict) else None
    return context if isinstance(context, dict) else None


def context_mcp_identity(kind: str, request: dict[str, Any]) -> dict[str, Any] | None:
    """Transport MCP identity inputs to native authority; never synthesize identity."""
    result = native_context_digest(
        kind,
        {"request": request},
        guard_home=_resolve_digest_home(None),
    )
    if not isinstance(result, dict) or result.get("status") != "ok":
        # The runtime answered and refused.  Its own code is the only thing
        # that says why, and a caller with no fallback aborts an install on
        # this; without it the person reading the error is told the identity
        # was unavailable and nothing about the answer that said so.
        _record_refusal(result)
        return None
    identity = result.get(kind)
    return identity if isinstance(identity, dict) else None


def _record_refusal(result: object) -> None:
    """Keep an error-status answer's own code as the failure reason."""

    if not isinstance(result, dict) or _LAST_DIGEST_FAILURE.get() is not None:
        return
    code = result.get("code")
    if isinstance(code, str) and code:
        _digest_failed(code)


_MCP_RISK_CATEGORIES = frozenset(
    {
        "filesystem_access",
        "command_execution",
        "destructive_mutation",
        "outbound_network",
        "privileged_system_mutation",
        "secret_access",
        "tool_schema_mismatch",
        "browser_navigation",
        "browser_inspection",
        "browser_interaction",
        "browser_transfer",
        "browser_privileged",
        "browser_external_domain",
        "browser_shared_profile",
        "browser_sensitive_surface",
    }
)


def context_browser_mcp(request: dict[str, Any]) -> dict[str, Any]:
    """Project native browser semantics; native absence is not a negative match."""
    result = native_context_digest(
        "browser_mcp",
        {"request": request},
        guard_home=_resolve_digest_home(None),
    )
    browser = result.get("browser_mcp") if isinstance(result, dict) and result.get("status") == "ok" else None
    if not isinstance(browser, dict) or browser.get("operation") != request.get("operation"):
        raise _unavailable("native_browser_mcp_intent_unavailable")
    return browser


def context_mcp_redact_json(value: object) -> object:
    """stdio `_redact_json` parity for recorded MCP traffic; terminal on failure."""
    fields = json.loads(json.dumps({"material": value}))
    result = native_context_digest(
        "mcp_redact_json",
        fields,
        guard_home=_resolve_digest_home(None),
    )
    if not isinstance(result, dict) or result.get("status") != "ok" or "mcp_redacted_value" not in result:
        raise _unavailable("native_mcp_redact_json_unavailable")
    return result["mcp_redacted_value"]


__all__ = [
    "bind_context_digest_home",
    "bind_context_digest_lifecycle_budget",
    "bound_context_digest_home",
    "context_browser_mcp",
    "context_digest_guard_home",
    "context_mcp_identity",
    "context_mcp_redact_json",
    "context_mcp_tool_catalog_fingerprint",
    "context_package_evidence",
    "context_runtime_executable_identity",
    "context_runtime_launch_identity",
    "context_runtime_launch_identity_matches",
    "context_runtime_launch_identity_projection",
    "context_sha256_digest",
    "is_unbound_context_digest",
    "native_context_digest",
    "reset_context_digest_budget",
    "reset_context_digest_home",
]
