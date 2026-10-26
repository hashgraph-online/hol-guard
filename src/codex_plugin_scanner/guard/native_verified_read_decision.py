"""Typed client for the native verified-read decisions; no Python composition."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any

from . import native_execution
from .native_context import _canonical_request_sha256, _resolve_digest_home, ensure_resident_prerequisite
from .native_runtime import native_runtime_status
from .native_runtime_resilience import native_record_resident_failure, native_record_resident_success

if TYPE_CHECKING:
    from .native_runtime_values import NativeRuntimeIdentity
    from .runtime.effect_decision import EffectDecision

_FEATURE = "verified-read-decision-v1"
_REQUEST_SCHEMA = "guard-verified-read-decision-request.v1"
_RESULT_SCHEMA = "guard-verified-read-decision-result.v1"
_RESULT_KEYS = frozenset({"schema", "request_id", "request_sha256", "status", "code", "decision"})
# The resident accepts a canonical request up to 16 KiB; the wire envelope
# carries the same material plus framing, so leave room for both.
_MAX_REQUEST_BYTES = 16 * 1024
_MAX_WIRE_BYTES = 6 * _MAX_REQUEST_BYTES + 4096


class NativeVerifiedReadDecisionError(RuntimeError):
    """The native owner could not supply a complete, request-bound decision."""


def workspace_read_decision(
    *,
    operation_id: str,
    binding_digest: str,
    guard_home: Path | None = None,
    timeout_seconds: float = 10.0,
) -> EffectDecision:
    """Return the resident's decision for a verified workspace read."""

    read: dict[str, object] = {"kind": "workspace", "operation_id": operation_id}
    return _request_decision(read, binding_digest, guard_home=guard_home, timeout_seconds=timeout_seconds)


def github_public_read_decision(
    *,
    binding_digest: str,
    guard_home: Path | None = None,
    timeout_seconds: float = 10.0,
) -> EffectDecision:
    """Return the resident's decision for a verified GitHub public read."""

    read: dict[str, object] = {"kind": "github_public_read"}
    return _request_decision(read, binding_digest, guard_home=guard_home, timeout_seconds=timeout_seconds)


def _request_decision(
    read: dict[str, object],
    binding_digest: str,
    *,
    guard_home: Path | None,
    timeout_seconds: float,
) -> EffectDecision:
    """Ask the resident for one verified-read decision and verify it answers this request.

    The decision is what lets a proven read run without an approval, so it has
    exactly one composition and the resident owns it. Every outcome other than
    a well-formed, request-bound ``ok`` reply raises
    ``NativeVerifiedReadDecisionError``; callers must not compose a local
    decision instead, which would be a second place a read can be allowed.
    """

    wire: dict[str, object] = {
        "schema": _REQUEST_SCHEMA,
        "request_id": native_execution._request_id("verified_read_decision"),
        "binding_digest": binding_digest,
        "read": read,
    }
    try:
        home = _resolve_digest_home(guard_home)
        if not ensure_resident_prerequisite(home):
            raise NativeVerifiedReadDecisionError("native_verified_read_decision_unavailable")
        request_sha256 = _canonical_request_sha256(wire)
        # Resolved once: the transport and the health record below must name
        # the same binary, and the lookup walks the runtime on disk.
        status = native_runtime_status()
        decoded = native_execution._resident_request(
            operation="verified_read_decision",
            request=wire,
            guard_home=home,
            timeout_seconds=timeout_seconds,
            required_feature=_FEATURE,
            response_schema=_RESULT_SCHEMA,
            max_request_bytes=_MAX_WIRE_BYTES,
            # Success is recorded below, once the reply is known to be usable.
            record_success=False,
            status=status,
        )
    except (OSError, TypeError, ValueError) as error:
        raise NativeVerifiedReadDecisionError("native_verified_read_decision_unavailable") from error
    if decoded is None:
        raise NativeVerifiedReadDecisionError("native_verified_read_decision_unavailable")
    try:
        decision = _validated_decision(decoded, wire, request_sha256)
    except NativeVerifiedReadDecisionError:
        _record(home, status.identity, success=False)
        raise
    _record(home, status.identity, success=True)
    return decision


def _validated_decision(decoded: dict[str, Any], wire: dict[str, object], request_sha256: str) -> EffectDecision:
    if set(decoded) != _RESULT_KEYS or decoded.get("code") != "ok":
        raise NativeVerifiedReadDecisionError("native_verified_read_decision_invalid_result")
    if decoded.get("request_id") != wire["request_id"] or decoded.get("request_sha256") != request_sha256:
        raise NativeVerifiedReadDecisionError("native_verified_read_decision_request_mismatch")
    payload: Any = decoded.get("decision")
    if not isinstance(payload, dict):
        raise NativeVerifiedReadDecisionError("native_verified_read_decision_invalid_result")
    try:
        return native_execution._effect_decision(payload)
    except (AttributeError, TypeError, ValueError) as error:
        # The shared decoder reads each reason with ``.get``, so a reason that
        # is not an object surfaces as AttributeError.
        raise NativeVerifiedReadDecisionError("native_verified_read_decision_invalid_result") from error


def _record(home: Path, identity: NativeRuntimeIdentity | None, *, success: bool) -> None:
    if identity is None:
        return
    if success:
        native_record_resident_success(identity.sha256, home)
    else:
        native_record_resident_failure(identity.sha256, home, reason="native_verified_read_decision_result")
