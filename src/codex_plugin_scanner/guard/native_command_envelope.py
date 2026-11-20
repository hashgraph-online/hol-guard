"""Resident bridge for the ``command_envelope`` op.

Rust owns the HMAC around Guard Cloud's command flow: the capability the local
CLI issues, the grant a user writes when they confirm a leased job, and the
identity digest the replay rows and those grants are matched by. This module
ships the payload and the caller's copy of the local signing key, binds the
reply by ``request_id`` plus ``request_sha256`` and hands the answer back.
Nothing is signed, checked or digested here, so an unavailable resident can
neither mint an approval token nor accept one.

The binding digest deliberately excludes the signing key: the wire carries the
real ``integrity_key_b64`` while both sides digest a copy whose value is null,
so a reply, log or diagnostic quoting ``request_sha256`` reveals nothing about
the secret.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any
from uuid import uuid4

from .native_context import _resolve_digest_home, ensure_resident_prerequisite
from .native_execution import _resident_request
from .native_store_policy import _payload

COMMAND_ENVELOPE_FEATURE = "command-envelope-v1"
_REQUEST_SCHEMA = "guard-command-envelope-request.v1"
_RESULT_SCHEMA = "guard-command-envelope-result.v1"
_TIMEOUT_SECONDS = 10.0
_MAX_REQUEST_BYTES = 4 * 1024 * 1024


class CommandEnvelopeUnavailableError(RuntimeError):
    """The resident gave no answer, so no local approval token may be used."""

    reason: str = "native_command_envelope_unavailable"


def native_command_envelope(
    *,
    action: str,
    payload: object,
    integrity_key_b64: str | None,
    integrity_key_id: str | None,
    guard_home: Path | None = None,
) -> dict[str, object]:
    """Sign, verify or digest one envelope in the runtime.

    ``action`` is ``sign``, ``verify`` or ``digest``. The answer carries
    ``accepted``; when it is false ``reason`` holds the runtime's refusal code,
    and when it is true ``result`` holds the signed envelope, the verified
    envelope's unsigned fields, or the digest.
    """

    home = Path(_resolve_digest_home(guard_home))
    if not ensure_resident_prerequisite(home):
        raise CommandEnvelopeUnavailableError
    wire: dict[str, Any] = {
        "schema": _REQUEST_SCHEMA,
        "request_id": f"command-envelope-{uuid4().hex}",
        "action": action,
        "payload": payload,
        "integrity_key_b64": integrity_key_b64,
        "integrity_key_id": integrity_key_id,
    }
    try:
        response = _resident_request(
            operation="command_envelope",
            request=wire,
            guard_home=home,
            timeout_seconds=_TIMEOUT_SECONDS,
            required_feature=COMMAND_ENVELOPE_FEATURE,
            response_schema=_RESULT_SCHEMA,
            max_request_bytes=_MAX_REQUEST_BYTES,
            record_success=False,
        )
    except (TypeError, ValueError, OSError, RuntimeError):
        raise CommandEnvelopeUnavailableError from None
    answer = _payload(response, {**wire, "integrity_key_b64": None}, home)
    if not isinstance(answer, dict):
        raise CommandEnvelopeUnavailableError
    return answer
