"""Resident bridge for the ``command_capability`` op.

Rust owns whether Guard Cloud's remote-command capability is genuine and what
it lets a leased job do: the HMAC over the signed envelope, the version, issuer
and clock bindings, the device and workspace it names, the operations it still
grants, the job's identity, and whether that job was already admitted. This
module reads the stored envelope, the signing key, the resolved binding and the
replay rows, ships them once, binds the reply by ``request_id`` plus
``request_sha256`` and hands the verdict back. Nothing is recomputed here, so
an unavailable resident can never authorize a command.

The binding digest deliberately excludes the signing key: the wire carries the
real ``integrity_key_b64`` while both sides digest a copy whose value is null,
so a reply, log or diagnostic quoting ``request_sha256`` reveals nothing about
the secret.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any
from uuid import uuid4

from .native_context import _resolve_digest_home, ensure_resident_prerequisite
from .native_execution import _resident_request
from .native_store_policy import _payload

COMMAND_CAPABILITY_FEATURE = "command-capability-v1"
_REQUEST_SCHEMA = "guard-command-capability-request.v1"
_RESULT_SCHEMA = "guard-command-capability-result.v1"
_TIMEOUT_SECONDS = 10.0
_MAX_REQUEST_BYTES = 4 * 1024 * 1024


class CommandCapabilityUnavailableError(RuntimeError):
    """The resident gave no verdict, so no remote command may be authorized."""

    reason: str = "native_command_capability_unavailable"


def native_command_capability(
    *,
    capability: object,
    integrity_key_b64: str | None,
    integrity_key_id: str | None,
    device_id: str | None,
    workspace_id: str | None,
    oauth_error: str | None,
    now: str,
    job: Mapping[str, object] | None,
    schema_versions: Mapping[str, object],
    replay_items: Sequence[object],
    replay_identity: Mapping[str, object] | None = None,
    guard_home: Path | None = None,
) -> dict[str, object]:
    """Verify the stored capability, and authorize ``job`` when one is given.

    The answer carries ``capability_valid`` with the envelope's own failure
    ``reason`` when it is not, the projected ``operations``, and - when ``job``
    is not ``None`` - an ``authorization`` naming the job's identity and
    whether it still needs a local confirmation. A ``replay_identity`` asks the
    separate question a caller with its own authorization needs: ``replayed``
    says whether the replay rows already hold that identity.
    """

    home = Path(_resolve_digest_home(guard_home))
    if not ensure_resident_prerequisite(home):
        raise CommandCapabilityUnavailableError
    wire: dict[str, Any] = {
        "schema": _REQUEST_SCHEMA,
        "request_id": f"command-capability-{uuid4().hex}",
        "capability": capability,
        "integrity_key_b64": integrity_key_b64,
        "integrity_key_id": integrity_key_id,
        "device_id": device_id,
        "workspace_id": workspace_id,
        "oauth_error": oauth_error,
        "now": now,
        "job": dict(job) if job is not None else None,
        "schema_versions": dict(schema_versions),
        "replay_items": list(replay_items),
        "replay_identity": dict(replay_identity) if replay_identity is not None else None,
    }
    try:
        response = _resident_request(
            operation="command_capability",
            request=wire,
            guard_home=home,
            timeout_seconds=_TIMEOUT_SECONDS,
            required_feature=COMMAND_CAPABILITY_FEATURE,
            response_schema=_RESULT_SCHEMA,
            max_request_bytes=_MAX_REQUEST_BYTES,
            record_success=False,
        )
    except (TypeError, ValueError, OSError, RuntimeError):
        raise CommandCapabilityUnavailableError from None
    payload = _payload(response, {**wire, "integrity_key_b64": None}, home)
    if not isinstance(payload, dict):
        raise CommandCapabilityUnavailableError
    return payload


COMMAND_CAPABILITY_ISSUE_FEATURE = "command-capability-issue-v1"
_ISSUE_REQUEST_SCHEMA = "guard-command-capability-issue-request.v1"
_ISSUE_RESULT_SCHEMA = "guard-command-capability-issue-result.v1"
_ISSUE_MAX_REQUEST_BYTES = 256 * 1024


def native_command_capability_issue(
    *,
    requested: Sequence[str],
    supported_operations: Sequence[str],
    issuer: str,
    ttl_seconds: int,
    guard_home: Path | None = None,
) -> dict[str, object]:
    """Decide which operations a new capability may carry.

    ``requested`` is the ``--operations`` words as the user typed them: the
    group name, comma-joined lists and stray spacing all reach the resident
    unexpanded, so what a grant can authorize is decided once. The answer says
    whether it is ``granted``, the exact ``operations`` it carries, and the
    refusal ``reason`` when it is not.
    """

    home = Path(_resolve_digest_home(guard_home))
    if not ensure_resident_prerequisite(home):
        raise CommandCapabilityUnavailableError
    wire: dict[str, Any] = {
        "schema": _ISSUE_REQUEST_SCHEMA,
        "request_id": f"command-capability-issue-{uuid4().hex}",
        "requested": [str(word) for word in requested],
        "supported_operations": [str(operation) for operation in supported_operations],
        "issuer": issuer,
        "ttl_seconds": int(ttl_seconds),
    }
    try:
        response = _resident_request(
            operation="command_capability_issue",
            request=wire,
            guard_home=home,
            timeout_seconds=_TIMEOUT_SECONDS,
            required_feature=COMMAND_CAPABILITY_ISSUE_FEATURE,
            response_schema=_ISSUE_RESULT_SCHEMA,
            max_request_bytes=_ISSUE_MAX_REQUEST_BYTES,
            record_success=False,
        )
    except (TypeError, ValueError, OSError, RuntimeError):
        raise CommandCapabilityUnavailableError from None
    payload = _payload(response, wire, home)
    if not isinstance(payload, dict):
        raise CommandCapabilityUnavailableError
    return payload
