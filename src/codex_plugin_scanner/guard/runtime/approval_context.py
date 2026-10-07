"""Opaque context binding for saved runtime approvals.

Approval evidence is valid only for the context that was reviewed.  These
tokens bind the five context dimensions that can invalidate a saved approval
without persisting their potentially sensitive source values.  The token is
not an authority or a signature; consumers must still resolve and claim saved
approval evidence through the policy store.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Literal, TypeGuard, cast

from ..native_context import _UNBOUND_PREFIX
from .extension_control_runtime import current_extension_control_binding_digest

APPROVAL_CONTEXT_TOKEN_PREFIX = "guard-approval-context:v1:"

ApprovalContextValidationFailure = Literal[
    "approval_reuse_identity_changed",
    "approval_reuse_content_changed",
    "approval_reuse_capability_changed",
    "approval_reuse_policy_changed",
    "approval_reuse_sandbox_changed",
]

_TOKEN_VERSION = 1
_TOKEN_FIELDS = frozenset({"version", "identity", "content", "capabilities", "policy", "sandbox"})
_ENCODED_PAYLOAD_PATTERN = re.compile(r"^[A-Za-z0-9_-]+$")
_SHA256_HEX_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_MAX_TOKEN_LENGTH = 2048


@dataclass(frozen=True, slots=True)
class ApprovalContextToken:
    """Parsed, non-secret approval-context component digests."""

    identity_hash: str
    content_hash: str
    capabilities_hash: str
    policy_hash: str
    sandbox_hash: str


class NativeContextDigestUnavailableError(RuntimeError):
    """The native context-digest authority is required but unreachable."""


def _unbound_context_digest(label: str, *, material: object) -> str:
    """Return a degraded sentinel that can never validate as context proof.

    Builders degrade to this when the native digest authority is unreachable
    (``HOL_GUARD_NATIVE=off``, missing runtime, unprovisioned home).  The
    ``guard-context-unbound:`` prefix is rejected by token parsing and by
    ``is_unbound_context_digest`` call sites, so equality between two degraded
    values can never mint approval reuse or an unchanged-context claim.
    Determinism over the caller's canonical ``material`` maps identical
    degraded inputs to one sentinel, so restrictive stored rows (saved
    blocks) keyed by artifact hash stay reachable, while validation still
    rejects every unbound value on sight.
    """

    canonical = json.dumps(
        {"label": label, "material": material},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")
    return f"{_UNBOUND_PREFIX}{label}:{hashlib.sha256(canonical).hexdigest()}"


@lru_cache(maxsize=4)
def _context_digest_guard_home(home: str) -> Path:
    """Resolve the resident's guard home, cached per user home."""

    from ..config import resolve_guard_home_for_user_home

    return resolve_guard_home_for_user_home(Path(home))


def _context_digest_result(kind: str, fields: dict[str, object]) -> dict[str, object]:
    """Run one native ``context_digest`` sub-operation.

    The Rust worker owns the canonical encoding and hashing; this wrapper only
    transports the request and projects the typed result.  ``None`` (runtime
    unavailable, overloaded, or unbindable) raises the dedicated error, and a
    worker-side input rejection maps back to the legacy ``TypeError``
    boundary.

    Enforcement entry points bind their deployment's guard home so digest
    calls reach that flow's resident; unbound callers resolve the default
    home for this process.
    """

    from ..native_context import context_digest_guard_home, native_context_digest

    result = native_context_digest(
        kind,
        fields,
        guard_home=context_digest_guard_home() or _context_digest_guard_home(str(Path.home())),
    )
    if result is None:
        raise NativeContextDigestUnavailableError("native context digest authority unavailable")
    if result.get("status") != "ok":
        raise TypeError(f"approval context digest rejected input: {result.get('code')}")
    return result


def _require_json_component(name: str, value: object) -> None:
    try:
        json.dumps(value, ensure_ascii=True, allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise TypeError(f"approval context component {name!r} must be JSON-compatible") from exc


def _json_serializable(value: object) -> bool:
    try:
        json.dumps(value, ensure_ascii=True, allow_nan=False)
    except (TypeError, ValueError):
        return False
    return True


def build_approval_context_token(
    *,
    identity: object,
    content: object,
    capabilities: object,
    policy: object,
    sandbox: object,
) -> str:
    """Build a deterministic token from JSON-compatible context components.

    Mapping keys are canonicalized, so their insertion order does not affect
    the result.  Each component is hashed independently with a domain label;
    only those digests are serialized into the returned token.  In particular,
    ``content`` may be any artifact-hash text and is never parsed or embedded.
    """

    for name, value in (
        ("identity", identity),
        ("content", content),
        ("capabilities", capabilities),
        ("policy", policy),
        ("sandbox", sandbox),
    ):
        _require_json_component(name, value)
    components: dict[str, object] = {
        "identity": identity,
        "content": content,
        "capabilities": capabilities,
        "policy": policy,
        "sandbox": sandbox,
        "extension_control_digest": current_extension_control_binding_digest(),
    }
    try:
        result = _context_digest_result(
            "build_approval_context_token",
            {"components": components},
        )
    except NativeContextDigestUnavailableError:
        # Degrade deterministically over the already-validated components: the
        # unbound prefix still fails every validation path, but stored
        # restrictive rows (saved blocks) keyed by this token stay reachable
        # across identical degraded invocations.
        return _unbound_context_digest("approval-context-token", material=components)
    return cast(str, result["token"])


def parse_approval_context_token(token: object) -> ApprovalContextToken | None:
    """Parse a well-formed v1 token, returning ``None`` for legacy/malformed input."""

    if not isinstance(token, str) or not token.startswith(APPROVAL_CONTEXT_TOKEN_PREFIX):
        return None
    if len(token) > _MAX_TOKEN_LENGTH:
        return None
    encoded = token[len(APPROVAL_CONTEXT_TOKEN_PREFIX) :]
    if not encoded or _ENCODED_PAYLOAD_PATTERN.fullmatch(encoded) is None:
        return None
    padding = "=" * (-len(encoded) % 4)
    try:
        raw_payload = base64.b64decode(
            f"{encoded}{padding}".encode("ascii"),
            altchars=b"-_",
            validate=True,
        )
        payload = json.loads(raw_payload.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, json.JSONDecodeError):
        return None
    if not isinstance(payload, Mapping) or set(payload) != _TOKEN_FIELDS:
        return None
    if payload.get("version") != _TOKEN_VERSION:
        return None
    identity_hash = payload.get("identity")
    content_hash = payload.get("content")
    capabilities_hash = payload.get("capabilities")
    policy_hash = payload.get("policy")
    sandbox_hash = payload.get("sandbox")
    if not (
        _is_sha256_hex(identity_hash)
        and _is_sha256_hex(content_hash)
        and _is_sha256_hex(capabilities_hash)
        and _is_sha256_hex(policy_hash)
        and _is_sha256_hex(sandbox_hash)
    ):
        return None
    return ApprovalContextToken(
        identity_hash=identity_hash,
        content_hash=content_hash,
        capabilities_hash=capabilities_hash,
        policy_hash=policy_hash,
        sandbox_hash=sandbox_hash,
    )


def approval_context_validation_reason(
    saved_token: object,
    *,
    identity: object,
    content: object,
    capabilities: object,
    policy: object,
    sandbox: object,
) -> ApprovalContextValidationFailure | None:
    """Return the first changed context dimension for saved approval evidence."""

    for name, value in (
        ("identity", identity),
        ("content", content),
        ("capabilities", capabilities),
        ("policy", policy),
        ("sandbox", sandbox),
    ):
        _require_json_component(name, value)
    if not _json_serializable(saved_token):
        return "approval_reuse_content_changed"
    try:
        result = _context_digest_result(
            "validate_approval_context",
            {
                "saved_token": saved_token,
                "components": {
                    "identity": identity,
                    "content": content,
                    "capabilities": capabilities,
                    "policy": policy,
                    "sandbox": sandbox,
                    "extension_control_digest": current_extension_control_binding_digest(),
                },
            },
        )
    except (NativeContextDigestUnavailableError, TypeError):
        # The resident being unreachable — or a component it cannot express —
        # can never prove context is unchanged.  Deny reuse instead of
        # crashing the enforcement caller.
        return "approval_reuse_content_changed"
    return cast(ApprovalContextValidationFailure | None, result.get("validation_reason"))


def approval_context_tokens_validation_reason(
    saved_token: object,
    current_token: object,
) -> ApprovalContextValidationFailure | None:
    """Compare opaque saved/current tokens without requiring their raw context.

    Legacy artifact hashes and malformed tokens cannot prove that all context
    dimensions are unchanged, so they fail closed as changed content.
    """

    if not (_json_serializable(saved_token) and _json_serializable(current_token)):
        return "approval_reuse_content_changed"
    try:
        result = _context_digest_result(
            "validate_approval_context_tokens",
            {"saved_token": saved_token, "current_token": current_token},
        )
    except (NativeContextDigestUnavailableError, TypeError):
        return "approval_reuse_content_changed"
    return cast(ApprovalContextValidationFailure | None, result.get("validation_reason"))


def saved_allow_context_validation_reason(
    decision: Mapping[str, object],
    *,
    artifact_hash: str,
) -> str | None:
    """Validate only stored allows and fail closed on stale context tokens."""

    if decision.get("action") != "allow":
        return None
    return approval_context_tokens_validation_reason(decision.get("artifact_hash"), artifact_hash)


def build_runtime_executable_identity(
    command: object,
    *,
    search_path: str | None = None,
    cwd: Path | None = None,
    home_dir: Path | None = None,
    require_executable: bool = True,
) -> dict[str, object]:
    """Resolve and content-bind an executable without launching it.

    Resolution, hashing, symlink-chain snapshotting, and per-evaluation
    nonce semantics live in the native ``runtime_executable_identity``
    context-digest kind; this wrapper only transports the call. Files that
    cannot be safely and completely hashed receive a per-evaluation nonce —
    that deliberately disables approval reuse instead of treating an
    incomplete executable identity as stable.
    """

    from ..native_context import context_runtime_executable_identity

    return context_runtime_executable_identity(
        command,
        search_path=search_path,
        cwd=cwd,
        home_dir=home_dir,
        require_executable=require_executable,
    )


def build_runtime_launch_identity(
    command: object,
    *,
    args: Sequence[object] = (),
    structured_command: bool = False,
    direct_executable: bool = False,
    search_path: str | None = None,
    cwd: Path | None = None,
    home_dir: Path | None = None,
    launch_env: Mapping[str, str] | None = None,
) -> dict[str, object]:
    """Content-bind an executable and any local code-bearing entrypoint.

    Launch-vector parsing, launcher tables, entrypoint resolution from the
    real launch cwd, and nonce semantics all live in the native
    ``runtime_launch_identity`` context-digest kind; this wrapper only
    transports the call. Ambiguous, unsupported, stdin-backed, or
    unreadable entrypoints receive a fresh nonce so saved approvals fail
    closed.
    """

    from ..native_context import context_runtime_launch_identity

    return context_runtime_launch_identity(
        command,
        args=args,
        structured_command=structured_command,
        direct_executable=direct_executable,
        search_path=search_path,
        cwd=cwd,
        home_dir=home_dir,
        launch_env=launch_env,
    )


def resolved_runtime_launch_executable(identity: Mapping[str, object]) -> str | None:
    """Return the verified canonical executable path pinned by a launch identity.

    Resolved by the native ``runtime_launch_identity_projection`` kind; the
    result intentionally returns ``None`` for unverified identities.
    """

    from ..native_context import context_runtime_launch_identity_projection

    _, executable, _ = context_runtime_launch_identity_projection(identity)
    return executable


def runtime_launch_identity_is_reusable(identity: Mapping[str, object]) -> bool:
    """Return whether every launch-identity dimension was proven stable."""

    from ..native_context import context_runtime_launch_identity_projection

    reusable, _, _ = context_runtime_launch_identity_projection(identity)
    return reusable


def resolved_runtime_launch_argv(
    identity: Mapping[str, object],
    *,
    args: Sequence[str] = (),
) -> tuple[str, ...] | None:
    """Return a path-pinned argv for a verified direct executable launch.

    Pinned by the native ``runtime_launch_identity_projection`` kind, which
    re-probes shebang bytes and resolves the interpreter chain without
    persisting raw shebang material in the identity.
    """

    from ..native_context import context_runtime_launch_identity_projection

    _, _, argv = context_runtime_launch_identity_projection(identity, args=args)
    return argv


def runtime_launch_identity_matches(
    expected_identity: Mapping[str, object],
    command: object,
    *,
    args: Sequence[object] = (),
    structured_command: bool = False,
    direct_executable: bool = False,
    search_path: str | None = None,
    cwd: Path | None = None,
    launch_env: Mapping[str, str] | None = None,
) -> bool:
    """Rebuild and compare all provable launch identity at a spawn boundary.

    Delegated to the native ``runtime_launch_identity_matches`` kind, which
    strips fresh ``reuse_nonce`` values (deliberately unprovable launch
    portions) and compares verification digests.  This remains a post-spawn
    containment check, not an atomic execution primitive — callers should
    launch the canonical executable returned by
    :func:`resolved_runtime_launch_executable`, validate immediately, and
    terminate the child before forwarding traffic on mismatch.
    """

    from ..native_context import context_runtime_launch_identity_matches

    return context_runtime_launch_identity_matches(
        expected_identity,
        command,
        args=args,
        structured_command=structured_command,
        direct_executable=direct_executable,
        search_path=search_path,
        cwd=cwd,
        launch_env=launch_env,
    )


def _configured_values_payload(
    values: Mapping[str, str] | object,
    configured_keys: Sequence[str] | None,
) -> dict[str, object]:
    """Shape configured values for transport without re-deriving semantics.

    ``str(key)`` mirrors the legacy normalization of non-string mapping keys;
    the worker applies the authoritative strip/dedup/framing.  Non-mapping
    inputs pass through so the worker reproduces the legacy failure boundary.
    """

    # Mappings travel as caller-ordered ["key", value] pairs: distinct raw
    # keys can collide after the worker strips whitespace, and the legacy dict
    # comprehension resolved the collision by the last entry in caller order —
    # an ordering a plain JSON object cannot carry across transport.
    if not values:
        pairs: object = []
    elif isinstance(values, Mapping):
        pairs = [[str(key), value] for key, value in values.items()]
    else:
        # Same boundary the legacy `.items()` AttributeError produced.
        raise TypeError("configured values must be a mapping or None")
    return {
        "values": pairs,
        "configured_keys": ([str(key) for key in configured_keys] if configured_keys is not None else None),
    }


def build_configured_environment_hash(
    environment: Mapping[str, str] | None,
    *,
    configured_keys: Sequence[str] | None = None,
) -> str:
    """Hash configured environment values without exposing or binding ambient values."""

    try:
        result = _context_digest_result(
            "configured_environment_hash",
            _configured_values_payload(environment, configured_keys),
        )
    except NativeContextDigestUnavailableError:
        # Deterministic so artifact content hashes don't churn; callers must
        # reject this sentinel rather than treat it as an exact binding.
        return f"{_UNBOUND_PREFIX}configured-environment"
    return cast(str, result["digest"])


def build_configured_header_values_hash(
    headers: Mapping[str, str] | None,
    *,
    configured_keys: Sequence[str] | None = None,
) -> str:
    """Hash configured header values without retaining or exposing them."""

    try:
        result = _context_digest_result(
            "configured_headers_hash",
            _configured_values_payload(headers, configured_keys),
        )
    except NativeContextDigestUnavailableError:
        # Deterministic so artifact content hashes don't churn; callers must
        # reject this sentinel rather than treat it as an exact binding.
        return f"{_UNBOUND_PREFIX}configured-headers"
    return cast(str, result["digest"])


def _is_sha256_hex(value: object) -> TypeGuard[str]:
    return isinstance(value, str) and _SHA256_HEX_PATTERN.fullmatch(value) is not None
