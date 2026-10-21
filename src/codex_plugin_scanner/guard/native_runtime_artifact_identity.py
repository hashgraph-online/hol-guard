"""Typed client for the native runtime artifact identities; no Python derivation."""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
from typing import TYPE_CHECKING

from . import native_execution
from .native_context import _canonical_request_sha256, _resolve_digest_home, ensure_resident_prerequisite
from .native_runtime import native_runtime_status
from .native_runtime_resilience import native_record_resident_failure, native_record_resident_success

if TYPE_CHECKING:
    from .native_runtime_values import NativeRuntimeIdentity

_FEATURE = "runtime-artifact-identity-v1"
_REQUEST_SCHEMA = "guard-runtime-artifact-identity-request.v1"
_RESULT_SCHEMA = "guard-runtime-artifact-identity-result.v1"
_RESULT_KEYS = frozenset({"schema", "request_id", "request_sha256", "status", "code", "artifact_id"})
# The resident accepts a canonical request up to 256 KiB. ``json.dumps``
# escapes every control character to six bytes, so the wire envelope can be
# several times larger than the request; leave that room plus the envelope.
_MAX_REQUEST_BYTES = 256 * 1024
_MAX_WIRE_BYTES = 6 * _MAX_REQUEST_BYTES + 4096
_HEX = "0123456789abcdef"


class NativeRuntimeArtifactIdentityError(RuntimeError):
    """The native owner could not supply a complete, request-bound artifact id."""


def data_flow_artifact_id(
    harness: str,
    *,
    source_scope: str,
    command_text: str,
    signal_ids: Sequence[str],
    guard_home: Path | None = None,
    timeout_seconds: float = 10.0,
) -> str:
    """Return the resident's artifact id for a data-flow exfiltration request."""

    identity: dict[str, object] = {
        "kind": "data_flow",
        "source_scope": source_scope,
        "command_text": command_text,
        "signal_ids": [str(item) for item in signal_ids],
    }
    return _request_identity(
        harness,
        identity,
        prefix=f"{harness}:{source_scope}:data-flow:",
        digest_chars=64,
        guard_home=guard_home,
        timeout_seconds=timeout_seconds,
    )


def _request_identity(
    harness: str,
    identity: dict[str, object],
    *,
    prefix: str,
    digest_chars: int,
    guard_home: Path | None,
    timeout_seconds: float,
) -> str:
    """Ask the resident for one runtime artifact id and verify it answers this request.

    The id is the key a saved approval is stored under, so it has exactly one
    derivation and the resident owns it. Every outcome other than a
    well-formed, request-bound ``ok`` reply raises
    ``NativeRuntimeArtifactIdentityError``; callers must not fall back to a
    Python fingerprint, which would re-key reviews the user already approved.
    """

    wire: dict[str, object] = {
        "schema": _REQUEST_SCHEMA,
        "request_id": native_execution._request_id("runtime_artifact_identity"),
        "harness": harness,
        "identity": identity,
    }
    try:
        home = _resolve_digest_home(guard_home)
        if not ensure_resident_prerequisite(home):
            raise NativeRuntimeArtifactIdentityError("native_runtime_artifact_identity_unavailable")
        request_sha256 = _canonical_request_sha256(wire)
        # Resolved once: the transport and the health record below must name
        # the same binary, and the lookup walks the runtime on disk.
        status = native_runtime_status()
        decoded = native_execution._resident_request(
            operation="runtime_artifact_identity",
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
        raise NativeRuntimeArtifactIdentityError("native_runtime_artifact_identity_unavailable") from error
    if decoded is None:
        raise NativeRuntimeArtifactIdentityError("native_runtime_artifact_identity_unavailable")
    try:
        artifact_id = _validated_artifact_id(decoded, wire, request_sha256, prefix=prefix, digest_chars=digest_chars)
    except NativeRuntimeArtifactIdentityError:
        _record(home, status.identity, success=False)
        raise
    _record(home, status.identity, success=True)
    return artifact_id


def _validated_artifact_id(
    decoded: dict[str, object],
    wire: dict[str, object],
    request_sha256: str,
    *,
    prefix: str,
    digest_chars: int,
) -> str:
    if set(decoded) != _RESULT_KEYS or decoded.get("code") != "ok":
        raise NativeRuntimeArtifactIdentityError("native_runtime_artifact_identity_invalid_result")
    if decoded.get("request_id") != wire["request_id"] or decoded.get("request_sha256") != request_sha256:
        raise NativeRuntimeArtifactIdentityError("native_runtime_artifact_identity_request_mismatch")
    artifact_id = decoded.get("artifact_id")
    if not isinstance(artifact_id, str) or not artifact_id.startswith(prefix):
        raise NativeRuntimeArtifactIdentityError("native_runtime_artifact_identity_invalid_result")
    digest = artifact_id[len(prefix) :]
    if len(digest) != digest_chars or any(character not in _HEX for character in digest):
        raise NativeRuntimeArtifactIdentityError("native_runtime_artifact_identity_invalid_result")
    return artifact_id


def _record(home: Path, identity: NativeRuntimeIdentity | None, *, success: bool) -> None:
    if identity is None:
        return
    if success:
        native_record_resident_success(identity.sha256, home)
    else:
        native_record_resident_failure(identity.sha256, home, reason="native_runtime_artifact_identity_result")
