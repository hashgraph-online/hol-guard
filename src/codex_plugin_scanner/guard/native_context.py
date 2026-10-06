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
from collections import OrderedDict
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from contextvars import ContextVar
from copy import deepcopy
from pathlib import Path
from typing import Any

from .directory_path_authority import canonical_guard_home_path
from .fork_safety import forget_in_child
from .native_resident_client import native_resident_client_request
from .native_response_decoder import native_error as _native_error
from .native_runtime import NativeRuntimeStatus, _isolated_environment, native_runtime_status
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
    "environment_values",
    "package_context",
    "mcp_server_identity",
    "mcp_tool_identity",
    "package_launcher",
    "mcp_descriptor",
    "browser_mcp",
    "mcp_tool_risk",
    "mcp_tool_policy",
    "mcp_launch_environment",
}
_RESULT_CODES = {
    "ok",
    "native_context_component_invalid",
    "native_context_values_invalid",
    "native_browser_argument_key_duplicated",
    "native_mcp_risk_pattern_failed",
    "native_mcp_risk_serialization_failed",
    "canonical_json_unencodable",
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
_RESULT_CACHE: OrderedDict[tuple[str, str], dict[str, Any]] = OrderedDict()
_RESULT_CACHE_MAX = 256
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


def _status_binary_unchanged(status: NativeRuntimeStatus) -> bool:
    """True while the on-disk binary still matches the memoized identity.

    ``stat()`` is cheap relative to re-hashing the whole binary, so checking
    ``size``/``mtime_ns`` per memo read keeps the reused status honest against
    a mid-window binary swap without paying the full re-validation cost.
    """

    identity = status.identity
    if identity is None:
        # No binary was validated (mode=off / unavailable).  There is nothing
        # to keep fresh, so the snapshot is reusable for the TTL.
        return True
    try:
        meta = Path(identity.path).stat()
    except OSError:
        return False
    return meta.st_size == identity.size and meta.st_mtime_ns == identity.mtime_ns


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
# ``validation_reason`` is legitimately null when context is unchanged, so
# validation kinds require field presence rather than a truthy value.
_OK_OUTPUT_FIELD: dict[str, str] = {
    "build_approval_context_token": "token",
    "configured_environment_hash": "digest",
    "configured_headers_hash": "digest",
    "launch_argv_digest": "digest",
    "canonical_sha256": "digest",
    "opaque_material_digest": "digest",
    "package_environment_policy": "environment_values",
    "mcp_server_identity": "mcp_server_identity",
    "mcp_tool_identity": "mcp_tool_identity",
    "mcp_server_descriptor": "mcp_descriptor",
    "mcp_tool_descriptor": "mcp_descriptor",
    "mcp_tool_content_digest": "digest",
    "browser_mcp": "browser_mcp",
    "package_launcher_token": "package_launcher",
}
_OK_NULLABLE_OUTPUT_FIELD: dict[str, str] = {
    "validate_approval_context": "validation_reason",
    "validate_approval_context_tokens": "validation_reason",
    "package_execution_context_from_evidence": "package_context",
    "package_execution_context_from_scanner_evidence": "package_context",
    "mcp_tool_risk": "mcp_tool_risk",
    "mcp_tool_policy": "mcp_tool_policy",
    # Either ``digest`` or ``token`` is present depending on the request's
    # config; ``mcp_tool_risk`` is always populated — the adapter validates.
    "build_mcp_tool_approval_hash": "mcp_tool_risk",
}


def _is_sha256_digest(value: object) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(character in "0123456789abcdef" for character in value)


def _valid_browser_projection(browser: Any) -> bool:
    if not isinstance(browser, dict):
        return False
    operation = browser.get("operation")
    intents = {"browser.navigation", "browser.inspect", "browser.interact", "browser.transfer", "browser.privileged"}
    if operation == "server":
        return set(browser) == {"operation", "is_browser"} and type(browser["is_browser"]) is bool
    if operation == "display":
        return set(browser) == {"operation", "target"} and isinstance(browser["target"], str)
    if operation == "classify":
        return set(browser) == {"operation", "intent"} and (
            browser["intent"] is None or (isinstance(browser["intent"], str) and browser["intent"] in intents)
        )
    if operation != "normalize" or set(browser) != {"operation", "intent"}:
        return False
    model = browser["intent"]
    if model is None:
        return True
    strings = {"intent", "operation", "method", "profile_mode", "mcp_server_name", "mcp_tool_name"}
    optional = {
        "target_url",
        "target_origin",
        "target_domain",
        "target_path_prefix",
        "mcp_server_identity_hash",
        "mcp_tool_identity_hash",
        "mcp_schema_hash",
    }
    lists = {"sensitive_surface_flags", "volatile_fields_dropped"}
    if (
        not isinstance(model, dict)
        or set(model) != strings | optional | lists | {"version"}
        or type(model["version"]) is not int
        or model["version"] != 1
        or any(not isinstance(model[key], str) for key in strings)
        or any(model[key] is not None and not isinstance(model[key], str) for key in optional)
        or any(not isinstance(model[key], list) for key in lists)
        or any(not isinstance(item, str) for key in lists for item in model[key])
    ):
        return False
    surfaces = {
        "cookies",
        "storage",
        "auth_headers",
        "cdp",
        "script_eval",
        "upload",
        "download",
        "clipboard",
        "network_intercept",
        "password_field",
    }
    return (
        model["intent"] in intents
        and model["method"] in {"navigate", "read", "interact", "upload", "privileged"}
        and model["profile_mode"] in {"isolated", "dedicated", "remote-debugging", "shared", "unknown"}
        and set(model["sensitive_surface_flags"]) <= surfaces
        and all(len(model[key]) == len(set(model[key])) for key in lists)
    )


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
    for field in ("token", "digest", "validation_reason"):
        value = payload.get(field)
        if value is not None and not isinstance(value, str):
            return None
    launcher = payload.get("package_launcher")
    if launcher is not None and (
        not isinstance(launcher, dict)
        or set(launcher) != {"package"}
        or (launcher["package"] is not None and not isinstance(launcher["package"], str))
    ):
        return None
    launch_environment = payload.get("mcp_launch_environment")
    if launch_environment is not None and (
        not isinstance(launch_environment, dict)
        or any(not isinstance(name, str) or not isinstance(value, str) for name, value in launch_environment.items())
    ):
        return None
    values = payload.get("environment_values")
    if values is not None and (
        not isinstance(values, dict)
        or any(
            not isinstance(name, str) or (digest is not None and not _is_sha256_digest(digest))
            for name, digest in values.items()
        )
    ):
        return None
    context = payload.get("package_context")
    if context is not None:
        if (
            not isinstance(context, dict)
            or set(context) != {"digest", "portable", "components", "non_portable_reason"}
            or not _is_sha256_digest(context["digest"])
            or not isinstance(context["portable"], bool)
            or not isinstance(context["components"], list)
            or not context["components"]
            or (context["non_portable_reason"] is not None and not isinstance(context["non_portable_reason"], str))
        ):
            return None
        for component in context["components"]:
            if (
                not isinstance(component, dict)
                or set(component) != {"name", "digest"}
                or not isinstance(component["name"], str)
                or not _is_sha256_digest(component["digest"])
            ):
                return None
    for field, string_fields, optional_fields, digest_fields in (
        (
            "mcp_server_identity",
            {"config_path", "command", "args_hash", "package_source", "transport", "env_values_hash", "identity_hash"},
            {"package_name", "package_version"},
            {"args_hash", "env_values_hash", "identity_hash"},
        ),
        (
            "mcp_tool_identity",
            {"server_hash", "tool_name", "schema_hash", "description_hash", "identity_hash"},
            set(),
            {"schema_hash", "description_hash", "identity_hash"},
        ),
    ):
        identity = payload.get(field)
        if identity is None:
            continue
        expected_fields = string_fields | optional_fields
        if field == "mcp_server_identity":
            expected_fields = expected_fields | {"env_keys"}
        if (
            not isinstance(identity, dict)
            or set(identity) != expected_fields
            or any(not isinstance(identity[key], str) for key in string_fields)
            or any(identity[key] is not None and not isinstance(identity[key], str) for key in optional_fields)
            or any(not _is_sha256_digest(identity[key]) for key in digest_fields)
        ):
            return None
        if field == "mcp_server_identity" and (
            not isinstance(identity["env_keys"], list) or any(not isinstance(key, str) for key in identity["env_keys"])
        ):
            return None
    descriptor = payload.get("mcp_descriptor")
    if descriptor is not None:
        if kind == "mcp_server_descriptor":
            strings = {
                "argsHash",
                "command",
                "commandHash",
                "configPath",
                "envValuesHash",
                "identityHash",
                "packageSource",
                "transport",
                "transportHash",
            }
            optional = {"dependencyHash", "packageName", "packageVersion", "publisherStableId"}
            hashes = {"argsHash", "commandHash", "envValuesHash", "identityHash", "transportHash"}
            optional_hashes = {"dependencyHash"}
            extra = {"envKeys"}
        elif kind == "mcp_tool_descriptor":
            strings = {"hashScope", "identityHash", "serverHash", "toolName"}
            optional = {"descriptionHash", "descriptorHash", "schemaHash"}
            hashes = {"identityHash"}
            optional_hashes = optional
            extra = set()
        else:
            return None
        if (
            not isinstance(descriptor, dict)
            or set(descriptor) != strings | optional | extra
            or any(not isinstance(descriptor[key], str) for key in strings)
            or any(descriptor[key] is not None and not isinstance(descriptor[key], str) for key in optional)
            or any(not _is_sha256_digest(descriptor[key]) for key in hashes)
            or any(descriptor[key] is not None and not _is_sha256_digest(descriptor[key]) for key in optional_hashes)
        ):
            return None
        if kind == "mcp_server_descriptor":
            publisher = descriptor["publisherStableId"]
            if (
                not isinstance(descriptor["envKeys"], list)
                or any(not isinstance(key, str) for key in descriptor["envKeys"])
                or (
                    publisher is not None
                    and (
                        not publisher.startswith("publisher:")
                        or not _is_sha256_digest(publisher.removeprefix("publisher:"))
                    )
                )
            ):
                return None
        elif descriptor["hashScope"] not in {"full", "manifest"}:
            return None
    browser = payload.get("browser_mcp")
    if browser is not None and (kind != "browser_mcp" or not _valid_browser_projection(browser)):
        return None
    categories = payload.get("mcp_tool_risk")
    if categories is not None and (
        kind not in {"mcp_tool_risk", "build_mcp_tool_approval_hash"}
        or not isinstance(categories, list)
        or any(not isinstance(category, str) or category not in _MCP_RISK_CATEGORIES for category in categories)
        or len(categories) != len(set(categories))
    ):
        return None
    policy = payload.get("mcp_tool_policy")
    if policy is not None and (kind != "mcp_tool_policy" or not _valid_mcp_tool_policy(policy)):
        return None
    if payload.get("status") == "ok":
        required_output = _OK_OUTPUT_FIELD.get(kind)
        nullable_output = _OK_NULLABLE_OUTPUT_FIELD.get(kind)
        if required_output is not None and not payload.get(required_output):
            return None
        if nullable_output is not None and nullable_output not in payload:
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

    status = _native_runtime_status_memo()
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
    deadline_budget_ms = max(1, min(9_000, int(timeout_seconds * 1_000)))
    deadline_monotonic = deadline_started + deadline_budget_ms / 1_000
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
            _canonical_request_sha256({"kind": kind, **kind_fields}) if kind != "mcp_launch_environment" else None
        )
    except (TypeError, ValueError):
        # Components the canonical encoder cannot express (non-JSON values,
        # non-finite floats) would fail inside the worker anyway; surface the
        # same failure boundary without shipping the request.
        return None
    # Canonicalize (including symlinks) so the same home spelled differently
    # cannot duplicate entries.  Path canonicalization is directory-path
    # authority, not transport work.
    # Launch environments contain granted credentials: do not retain them in
    # the digest result cache or hash the input a second time for caching.
    cache_key = (content_sha256, canonical_guard_home_path(guard_home)) if content_sha256 is not None else None
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
    strict: bool = True,
) -> str:
    """Canonical-JSON SHA-256 via the resident op.

    ``strict=True`` (default, for enforcement digests that gate equality):
    degrade to a ``guard-context-unbound:`` digest that fails every
    equality/validation check against a worker-issued value.

    ``strict=False`` (for identity/dedup digests that always produced a hex
    digest before this migration): degrade to the byte-identical local
    canonical hash so callers keep working when the resident is absent.  The
    value is byte-for-byte the same output the worker returns.
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
    if strict:
        return f"{_UNBOUND_PREFIX}{unbound_label}:{_unbound_material_digest(material)}"
    local = hashlib.sha256(_canonical_material_bytes(material)).hexdigest()
    return f"{prefix or ''}{local}"


def context_opaque_digest(
    material: str,
    *,
    guard_home: Path | None = None,
    unbound_label: str = "opaque-material",
    strict: bool = True,
) -> str:
    """UTF-8-string SHA-256 via the resident op.

    For raw string material (module specifiers, source text, ``h:s:n`` keys,
    shebang lines) — the bytes hashed are exactly ``material.encode("utf-8")``.
    ``strict`` semantics match :func:`context_sha256_digest`.
    """

    home = _resolve_digest_home(guard_home)
    result = native_context_digest(
        "opaque_material_digest",
        {"material": material},
        guard_home=home,
    )
    digest = result.get("digest") if isinstance(result, dict) else None
    if isinstance(digest, str) and digest:
        return digest
    if strict:
        return f"{_UNBOUND_PREFIX}{unbound_label}:{_unbound_material_digest(material)}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()  # codeql[py/weak-sensitive-data-hashing]


def context_package_environment_values(
    manager: str,
    environment: Mapping[str, str],
    referenced_names: Sequence[str],
    *,
    guard_home: Path | None = None,
) -> dict[str, str | None] | None:
    """Transport native package environment selection without a local fallback."""

    result = native_context_digest(
        "package_environment_policy",
        {
            "manager": manager,
            "environment": dict(environment),
            "referenced_names": list(referenced_names),
        },
        guard_home=_resolve_digest_home(guard_home),
    )
    values = result.get("environment_values") if isinstance(result, dict) else None
    return values if isinstance(values, dict) else None


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
        raise ValueError("native_mcp_launch_environment_unavailable")
    return values


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
    identity = result.get(kind) if isinstance(result, dict) and result.get("status") == "ok" else None
    return identity if isinstance(identity, dict) else None


def context_mcp_descriptor(kind: str, request: dict[str, Any]) -> dict[str, Any]:
    """Project native MCP descriptor semantics, without local synthesis."""
    result = native_context_digest(
        kind,
        {"request": request},
        guard_home=_resolve_digest_home(None),
    )
    if not isinstance(result, dict) or result.get("status") != "ok":
        raise ValueError("native_mcp_descriptor_unavailable")
    return result["mcp_descriptor"]


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


def context_mcp_tool_risk(artifact: dict[str, Any], arguments: object) -> tuple[str, ...]:
    """Transport argument representations; native categories remain authoritative."""
    fields = json.loads(json.dumps({"artifact": artifact, "arguments": arguments}, default=str))
    result = native_context_digest("mcp_tool_risk", fields, guard_home=_resolve_digest_home(None))
    categories = result.get("mcp_tool_risk") if isinstance(result, dict) and result.get("status") == "ok" else None
    if (
        not isinstance(categories, list)
        or any(not isinstance(category, str) or category not in _MCP_RISK_CATEGORIES for category in categories)
        or len(categories) != len(set(categories))
    ):
        raise ValueError("native_mcp_tool_risk_unavailable")
    return tuple(categories)


def _valid_mcp_tool_policy(policy: object) -> bool:
    if not isinstance(policy, dict) or set(policy) != {"action", "source", "summary_code", "risk_categories"}:
        return False
    categories = policy["risk_categories"]
    return (
        isinstance(policy["action"], str)
        and policy["action"] in {"allow", "warn", "review", "require-reapproval", "sandbox-required", "block"}
        and isinstance(policy["source"], str)
        and policy["source"] in {"heuristic", "browser-routine", "policy", "risk-policy"}
        and isinstance(policy["summary_code"], str)
        and policy["summary_code"] in {"no_risk", "risk", "configuration_stricter"}
        and isinstance(categories, list)
        and all(isinstance(category, str) and category in _MCP_RISK_CATEGORIES for category in categories)
        and len(categories) == len(set(categories))
    )


def context_mcp_tool_policy(request: dict[str, Any]) -> dict[str, Any]:
    fields = json.loads(json.dumps({"request": request}, default=str))
    result = native_context_digest("mcp_tool_policy", fields, guard_home=_resolve_digest_home(None))
    policy = result.get("mcp_tool_policy") if isinstance(result, dict) and result.get("status") == "ok" else None
    if not isinstance(policy, dict) or not _valid_mcp_tool_policy(policy):
        raise ValueError("native_mcp_tool_policy_unavailable")
    return policy


def context_browser_mcp(request: dict[str, Any]) -> dict[str, Any]:
    """Project native browser semantics; native absence is not a negative match."""
    result = native_context_digest(
        "browser_mcp",
        {"request": request},
        guard_home=_resolve_digest_home(None),
    )
    browser = result.get("browser_mcp") if isinstance(result, dict) and result.get("status") == "ok" else None
    if (
        not isinstance(browser, dict)
        or not _valid_browser_projection(browser)
        or browser["operation"] != request.get("operation")
    ):
        raise ValueError("native_browser_mcp_intent_unavailable")
    return browser


def context_package_launcher_token(command_name: str, args: Sequence[str]) -> str | None:
    """Project native launcher selection; absence is distinct from native failure."""
    result = native_context_digest(
        "package_launcher_token",
        {"command_name": command_name, "args": list(args)},
        guard_home=_resolve_digest_home(None),
    )
    if not isinstance(result, dict) or result.get("status") != "ok":
        raise ValueError("native_package_launcher_token_unavailable")
    return result["package_launcher"]["package"]


def context_mcp_tool_approval_hash(request: dict[str, Any], *, expect_token: bool) -> tuple[str, tuple[str, ...]]:
    """Compose the full MCP approval hash natively; no local fallback.

    Requests must be plain JSON types — the worker owns canonicalization, so
    no ``default=str`` coercion here (that would silently re-materialize big
    ints/sets as strings and change persisted digests).  Unencodable argument
    values hit the same ``component_invalid`` boundary the per-op adapters
    raised before.
    """
    try:
        fields = json.loads(json.dumps({"request": request}))
    except (TypeError, ValueError) as exc:
        raise ValueError("native_mcp_tool_approval_hash_unavailable") from exc
    result = native_context_digest(
        "build_mcp_tool_approval_hash",
        fields,
        guard_home=_resolve_digest_home(None),
    )
    if not isinstance(result, dict) or result.get("status") != "ok":
        raise ValueError("native_mcp_tool_approval_hash_unavailable")
    categories = result.get("mcp_tool_risk")
    if (
        not isinstance(categories, list)
        or any(not isinstance(category, str) or category not in _MCP_RISK_CATEGORIES for category in categories)
        or len(categories) != len(set(categories))
    ):
        raise ValueError("native_mcp_tool_approval_hash_unavailable")
    if expect_token:
        token = result.get("token")
        if not isinstance(token, str) or not token.startswith("guard-approval-context:v1:"):
            raise ValueError("native_mcp_tool_approval_hash_unavailable")
        return token, tuple(categories)
    digest = result.get("digest")
    if not isinstance(digest, str) or not _is_sha256_digest(digest):
        raise ValueError("native_mcp_tool_approval_hash_unavailable")
    return digest, tuple(categories)


__all__ = [
    "bind_context_digest_home",
    "bound_context_digest_home",
    "context_browser_mcp",
    "context_digest_guard_home",
    "context_mcp_descriptor",
    "context_mcp_identity",
    "context_mcp_tool_approval_hash",
    "context_mcp_tool_policy",
    "context_mcp_tool_risk",
    "context_opaque_digest",
    "context_package_environment_values",
    "context_package_evidence",
    "context_package_launcher_token",
    "context_sha256_digest",
    "is_unbound_context_digest",
    "native_context_digest",
    "reset_context_digest_home",
]
