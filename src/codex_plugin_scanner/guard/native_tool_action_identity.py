"""Typed client for the native tool-action artifact identity; no Python derivation."""

from __future__ import annotations

from pathlib import Path

from . import native_execution
from .native_context import _canonical_request_sha256, _resolve_digest_home, ensure_resident_prerequisite
from .native_runtime import native_runtime_status
from .native_runtime_resilience import native_record_resident_failure, native_record_resident_success
from .runtime.secret_file_request_services.request_models import ToolActionRequestMatch

_FEATURE = "tool-action-request-identity-v1"
_REQUEST_SCHEMA = "guard-tool-action-request-identity-request.v1"
_RESULT_SCHEMA = "guard-tool-action-request-identity-result.v1"
_RESULT_KEYS = frozenset({"schema", "request_id", "request_sha256", "status", "code", "artifact_id"})
# The resident accepts a canonical request up to 256 KiB. ``json.dumps``
# escapes every control character to six bytes, so the wire envelope can be
# several times larger than the request; leave that room plus the envelope.
_MAX_REQUEST_BYTES = 256 * 1024
_MAX_WIRE_BYTES = 6 * _MAX_REQUEST_BYTES + 4096


class NativeToolActionIdentityError(RuntimeError):
    """The native owner could not supply a complete, request-bound artifact id."""


def tool_action_request_artifact_id(
    harness: str,
    request: ToolActionRequestMatch,
    *,
    source_scope: str,
    guard_home: Path | None = None,
    timeout_seconds: float = 10.0,
) -> str:
    """Return the resident's artifact id for a sensitive tool-action request.

    The id is the key a saved approval is stored under, so it has exactly one
    derivation and the resident owns it. Every outcome other than a
    well-formed, request-bound ``ok`` reply raises
    ``NativeToolActionIdentityError``; callers must not fall back to a Python
    fingerprint, which would re-key reviews the user already approved.
    """

    wire: dict[str, object] = {
        "schema": _REQUEST_SCHEMA,
        "request_id": native_execution._request_id("tool_action_request_identity"),
        "harness": harness,
        "source_scope": source_scope,
        "normalized_tool_name": request.normalized_tool_name,
        "command_text": request.command_text,
        "action_class": request.action_class,
        "shell_execution_context_hash": request.shell_execution_context_hash,
        "interpreter_executable_identities": [dict(item) for item in request.interpreter_executable_identities],
        "script_read_identity_sha256": request.script_read_identity_sha256,
        "restricted_profile_version": request.restricted_profile_version,
        "pytest_config_identity_sha256": request.pytest_config_identity_sha256,
    }
    try:
        home = _resolve_digest_home(guard_home)
        if not ensure_resident_prerequisite(home):
            raise NativeToolActionIdentityError("native_tool_action_identity_unavailable")
        request_sha256 = _canonical_request_sha256(wire)
        decoded = native_execution._resident_request(
            operation="tool_action_request_identity",
            request=wire,
            guard_home=home,
            timeout_seconds=timeout_seconds,
            required_feature=_FEATURE,
            response_schema=_RESULT_SCHEMA,
            max_request_bytes=_MAX_WIRE_BYTES,
            # Success is recorded below, once the reply is known to be usable.
            record_success=False,
        )
    except (OSError, TypeError, ValueError) as error:
        raise NativeToolActionIdentityError("native_tool_action_identity_unavailable") from error
    if decoded is None:
        raise NativeToolActionIdentityError("native_tool_action_identity_unavailable")
    try:
        artifact_id = _bound_artifact_id(decoded, wire, request_sha256, f"{harness}:{source_scope}:tool-action:")
    except NativeToolActionIdentityError as error:
        # A refusal is a well-formed answer; anything else is a resident fault.
        if str(error) != "native_tool_action_identity_rejected":
            _record(home, success=False)
        raise
    _record(home, success=True)
    return artifact_id


def _bound_artifact_id(decoded: dict[str, object], wire: dict[str, object], request_sha256: str, prefix: str) -> str:
    if set(decoded) != _RESULT_KEYS:
        raise NativeToolActionIdentityError("native_tool_action_identity_invalid_result")
    if decoded.get("request_id") != wire["request_id"] or decoded.get("request_sha256") != request_sha256:
        raise NativeToolActionIdentityError("native_tool_action_identity_request_mismatch")
    if decoded.get("status") == "error":
        raise NativeToolActionIdentityError("native_tool_action_identity_rejected")
    if decoded.get("code") != "ok":
        raise NativeToolActionIdentityError("native_tool_action_identity_invalid_result")
    artifact_id = decoded.get("artifact_id")
    if not isinstance(artifact_id, str) or not artifact_id.startswith(prefix):
        raise NativeToolActionIdentityError("native_tool_action_identity_invalid_result")
    fingerprint = artifact_id[len(prefix) :]
    if len(fingerprint) != 64 or any(character not in "0123456789abcdef" for character in fingerprint):
        raise NativeToolActionIdentityError("native_tool_action_identity_invalid_result")
    return artifact_id


def _record(home: Path, *, success: bool) -> None:
    identity = native_runtime_status().identity
    if identity is None:
        return
    if success:
        native_record_resident_success(identity.sha256, home)
    else:
        native_record_resident_failure(identity.sha256, home, reason="native_tool_action_request_identity_result")
