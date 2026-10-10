"""Resident bridge for the ``cursor_observer_proof`` op.

Rust verifies the attestation proof a managed Cursor after-observer hook
presents: it reads the owner-private attestation key from the Guard home,
normalizes the command and checks the keyed digest. This module only sends the
presented fields, binds the reply by ``request_id`` plus ``request_sha256`` and
decodes it. Anything but a bound ``valid: true`` answer is not trusted;
nothing is ever verified in Python.
"""

from __future__ import annotations

from pathlib import Path
from uuid import uuid4

from .native_context import ensure_resident_prerequisite
from .native_execution import _resident_request
from .native_store_policy import _payload

CURSOR_OBSERVER_PROOF_FEATURE = "cursor-observer-proof-v1"
_REQUEST_SCHEMA = "guard-cursor-observer-proof-request.v1"
_RESULT_SCHEMA = "guard-cursor-observer-proof-result.v1"
_TIMEOUT_SECONDS = 5.0
_MAX_REQUEST_BYTES = 1024 * 1024


def native_cursor_observer_proof_valid(
    *,
    guard_home: Path,
    conversation_id: str,
    command: str,
    approval_binding: str,
    observer_event: str,
    proof: str,
    pending_proof: str | None = None,
    require_pending_match: bool = False,
) -> bool:
    """Whether the resident accepts the presented proof; False when it cannot say."""

    home = Path(guard_home)
    try:
        if not ensure_resident_prerequisite(home):
            return False
    except (OSError, RuntimeError, ValueError):
        return False
    wire: dict[str, object] = {
        "schema": _REQUEST_SCHEMA,
        "request_id": f"cursor-observer-proof-{uuid4().hex}",
        "guard_home": str(home),
        "conversation_id": conversation_id,
        "command": command,
        "approval_binding": approval_binding,
        "observer_event": observer_event,
        "proof": proof,
        "require_pending_match": require_pending_match,
        "pending_proof": pending_proof,
    }
    try:
        response = _resident_request(
            operation="cursor_observer_proof",
            request=wire,
            guard_home=home,
            timeout_seconds=_TIMEOUT_SECONDS,
            required_feature=CURSOR_OBSERVER_PROOF_FEATURE,
            response_schema=_RESULT_SCHEMA,
            max_request_bytes=_MAX_REQUEST_BYTES,
            record_success=False,
        )
    except (TypeError, ValueError):
        return False
    payload = _payload(response, wire, home)
    return payload is not None and payload.get("valid") is True
