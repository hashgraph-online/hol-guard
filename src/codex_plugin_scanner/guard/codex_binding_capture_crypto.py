"""Private cryptographic primitives for Codex binding diagnostics.

The capture feature is deliberately opt in.  This module only operates on a
validated, private v2 session marker and never provides an unkeyed fallback.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import secrets
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Final, cast

from .codex_binding_capture_bounds import (
    MAX_CANONICAL_PAYLOAD_BYTES,
    bounded_utf8_bytes,
    canonical_json_bytes,
    validate_json_value,
)
from .evaluation_json import reject_duplicate_keys
from .native_decision_receipt import validate_native_decision_receipt

CAPTURE_SCHEMA: Final = "guard-codex-binding-capture.v2"
LEGACY_CAPTURE_SCHEMA: Final = "guard-codex-binding-capture.v1"
FINGERPRINT_SCHEME: Final = "hmac-sha256-per-run-v2"
CAPTURE_KEY_BYTES: Final = 32
CAPTURE_NONCE_BYTES: Final = 12
CAPTURE_KEY_ID_HEX_BYTES: Final = 16
MAX_CAPTURE_RECORDS: Final = 128
MAX_CAPTURE_BYTES: Final = 64 * 1024
MAX_MARKER_BYTES: Final = 4 * 1024
MAX_RUN_ID_BYTES: Final = 64

_RUN_ID_RE: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$")
_KEY_ID_RE: Final = re.compile(r"^[0-9a-f]{32}$")
_HEX64_RE: Final = re.compile(r"^[0-9a-f]{64}$")
_MARKER_FIELDS: Final = frozenset(
    {
        "schema",
        "enabled",
        "run_id",
        "expires_at",
        "max_records",
        "max_bytes",
        "key_id",
        "capture_key_b64",
    }
)
_SEALED_RECEIPT_FIELDS: Final = frozenset({"nonce_b64", "ciphertext_b64"})
_RECEIPT_PROJECTION_FIELDS: Final = (
    "schema",
    "version",
    "authority",
    "decision_id",
    "request_id",
    "request_digest",
    "harness",
    "event_name",
    "payload_kind",
    "policy_generation",
    "policy_digest",
    "rule_digest",
    "runtime_identity",
    "decision",
    "model_output_action",
    "policy_action",
    "observed_policy_action",
    "reason_code",
    "workspace_bound",
    "source_ref_external_allowed",
    "reviewed_output_sha256",
    "observe_mode",
    "deadline_budget_ms",
)


@dataclass(frozen=True, slots=True)
class CaptureSession:
    """Validated in-memory session material read from a private marker."""

    run_id: str
    expires_at: int
    max_records: int
    max_bytes: int
    key_id: str
    key: bytes = field(repr=False, compare=False)


def receipt_projection(receipt: object) -> dict[str, object] | None:
    """Validate and retain the unchanged native receipt projection in memory."""

    try:
        validated = validate_native_decision_receipt(receipt)
    except RecursionError:
        return None
    if validated is None:
        return None
    projection = {key: validated[key] for key in _RECEIPT_PROJECTION_FIELDS}
    for key in ("command_extensions", "prompt_risk_classes"):
        if key in validated:
            projection[key] = validated[key]
    return projection


def _session_usable(session: object, *, now: float | None = None) -> bool:
    if not isinstance(session, CaptureSession):
        return False
    if type(session.run_id) is not str or not _RUN_ID_RE.fullmatch(session.run_id):
        return False
    if type(session.expires_at) is not int:
        return False
    if type(session.max_records) is not int or not 0 < session.max_records <= MAX_CAPTURE_RECORDS:
        return False
    if type(session.max_bytes) is not int or not 0 < session.max_bytes <= MAX_CAPTURE_BYTES:
        return False
    if type(session.key_id) is not str or not _KEY_ID_RE.fullmatch(session.key_id):
        return False
    if type(session.key) is not bytes or len(session.key) != CAPTURE_KEY_BYTES:
        return False
    current = time.time() if now is None else now
    return int(current) < session.expires_at <= int(current) + 3600


def new_capture_session(
    run_id: str,
    *,
    expires_at: int,
    max_records: int = MAX_CAPTURE_RECORDS,
    max_bytes: int = MAX_CAPTURE_BYTES,
    now: float | None = None,
) -> CaptureSession | None:
    """Create a fresh per-run session for an explicit marker initializer."""

    if type(run_id) is not str or not _RUN_ID_RE.fullmatch(run_id):
        return None
    session = CaptureSession(
        run_id=run_id,
        expires_at=expires_at,
        max_records=max_records,
        max_bytes=max_bytes,
        key_id=secrets.token_hex(CAPTURE_KEY_ID_HEX_BYTES),
        key=secrets.token_bytes(CAPTURE_KEY_BYTES),
    )
    if not _session_usable(session, now=now):
        return None
    return session


def marker_payload(session: CaptureSession) -> dict[str, object] | None:
    if not _session_usable(session):
        return None
    return {
        "schema": CAPTURE_SCHEMA,
        "enabled": True,
        "run_id": session.run_id,
        "expires_at": session.expires_at,
        "max_records": session.max_records,
        "max_bytes": session.max_bytes,
        "key_id": session.key_id,
        "capture_key_b64": base64.urlsafe_b64encode(session.key).decode("ascii"),
    }


def encode_marker(session: CaptureSession) -> bytes | None:
    payload = marker_payload(session)
    if payload is None:
        return None
    encoded = canonical_json_bytes(payload)
    if encoded is None or len(encoded) > MAX_MARKER_BYTES:
        return None
    return encoded + b"\n"


def _decode_b64(value: object, *, max_bytes: int) -> bytes | None:
    if type(value) is not str or not value or len(value) > max_bytes * 2:
        return None
    try:
        encoded = value.encode("ascii")
        decoded = base64.b64decode(encoded, altchars=b"-_", validate=True)
    except (UnicodeEncodeError, ValueError):
        return None
    if len(decoded) > max_bytes:
        return None
    if base64.urlsafe_b64encode(decoded).decode("ascii") != value:
        return None
    return decoded


def parse_marker(value: Mapping[str, object], *, now: float | None = None) -> CaptureSession | None:
    if frozenset(value) != _MARKER_FIELDS:
        return None
    if value.get("schema") != CAPTURE_SCHEMA or value.get("enabled") is not True:
        return None
    run_id = value.get("run_id")
    expires_at = value.get("expires_at")
    max_records = value.get("max_records")
    max_bytes = value.get("max_bytes")
    key_id = value.get("key_id")
    encoded_key = value.get("capture_key_b64")
    if (
        type(run_id) is not str
        or not _RUN_ID_RE.fullmatch(run_id)
        or type(expires_at) is not int
        or type(max_records) is not int
        or type(max_bytes) is not int
        or type(key_id) is not str
        or not _KEY_ID_RE.fullmatch(key_id)
    ):
        return None
    key = _decode_b64(encoded_key, max_bytes=CAPTURE_KEY_BYTES)
    if key is None or len(key) != CAPTURE_KEY_BYTES:
        return None
    session = CaptureSession(
        run_id=run_id,
        expires_at=expires_at,
        max_records=max_records,
        max_bytes=max_bytes,
        key_id=key_id,
        key=key,
    )
    return session if _session_usable(session, now=now) else None


def _domain(role: str) -> bytes:
    return f"{CAPTURE_SCHEMA}\x00{role}".encode("ascii")


def _keyed_digest(session: CaptureSession, role: str, payload: bytes) -> str | None:
    if not _session_usable(session):
        return None
    return hmac.new(session.key, _domain(role) + b"\x00" + payload, hashlib.sha256).hexdigest()


def payload_hmac(session: CaptureSession, role: str, payload: object) -> str | None:
    if role not in {"raw", "forwarded"}:
        return None
    encoded = canonical_json_bytes(payload)
    if encoded is None or len(encoded) > MAX_CANONICAL_PAYLOAD_BYTES:
        return None
    return _keyed_digest(session, role, encoded)


def row_hmac(session: CaptureSession, row: Mapping[str, object]) -> str | None:
    material = dict(row)
    _ = material.pop("row_mac", None)
    encoded = canonical_json_bytes(material)
    if encoded is None or len(encoded) > MAX_CAPTURE_BYTES:
        return None
    return _keyed_digest(session, "row", encoded)


def verify_row_hmac(session: CaptureSession, row: Mapping[str, object]) -> bool:
    expected = row.get("row_mac")
    actual = row_hmac(session, row)
    return (
        type(expected) is str
        and _HEX64_RE.fullmatch(expected) is not None
        and actual is not None
        and hmac.compare_digest(expected, actual)
    )


def row_aad(row: Mapping[str, object]) -> bytes | None:
    aad = {
        "schema": row.get("schema"),
        "run_id": row.get("run_id"),
        "key_id": row.get("key_id"),
        "harness": row.get("harness"),
        "event_name": row.get("event_name"),
        "tool_use_id_state": row.get("tool_use_id_state"),
        "tool_use_id": row.get("tool_use_id"),
        "route": row.get("route"),
        "raw_payload_hmac_sha256": row.get("raw_payload_hmac_sha256"),
        "forwarded_payload_hmac_sha256": row.get("forwarded_payload_hmac_sha256"),
    }
    return canonical_json_bytes(aad)


def seal_receipt(
    session: CaptureSession,
    row: Mapping[str, object],
    receipt: Mapping[str, object],
) -> dict[str, str] | None:
    if not _session_usable(session):
        return None
    plaintext = canonical_json_bytes(receipt)
    aad = row_aad(row)
    if plaintext is None or aad is None or len(plaintext) > MAX_CAPTURE_BYTES:
        return None
    # Import only after the marker and key have passed all validation above.
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError:
        return None

    nonce = secrets.token_bytes(CAPTURE_NONCE_BYTES)
    ciphertext = AESGCM(session.key).encrypt(nonce, plaintext, aad)
    return {
        "nonce_b64": base64.urlsafe_b64encode(nonce).decode("ascii"),
        "ciphertext_b64": base64.urlsafe_b64encode(ciphertext).decode("ascii"),
    }


def _decode_object(plaintext: bytes) -> dict[str, object] | None:
    if bounded_utf8_bytes(plaintext) is None:
        return None
    try:
        value = cast(object, json.loads(plaintext.decode("utf-8"), object_pairs_hook=reject_duplicate_keys))
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError):
        return None
    if type(value) is not dict or not validate_json_value(cast(object, value)):
        return None
    return cast(dict[str, object], value)


def open_receipt(
    session: CaptureSession,
    row: Mapping[str, object],
    sealed: Mapping[str, object],
) -> dict[str, object] | None:
    if not _session_usable(session) or frozenset(sealed) != _SEALED_RECEIPT_FIELDS:
        return None
    nonce = _decode_b64(sealed.get("nonce_b64"), max_bytes=CAPTURE_NONCE_BYTES)
    ciphertext = _decode_b64(sealed.get("ciphertext_b64"), max_bytes=MAX_CAPTURE_BYTES)
    aad = row_aad(row)
    if nonce is None or len(nonce) != CAPTURE_NONCE_BYTES or ciphertext is None or len(ciphertext) < 16 or aad is None:
        return None
    # Import only after the marker and key have passed all validation above.
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError:
        return None

    try:
        plaintext = AESGCM(session.key).decrypt(nonce, ciphertext, aad)
    except Exception:
        return None
    return _decode_object(plaintext)


__all__ = [
    "CAPTURE_KEY_BYTES",
    "CAPTURE_NONCE_BYTES",
    "CAPTURE_SCHEMA",
    "FINGERPRINT_SCHEME",
    "LEGACY_CAPTURE_SCHEMA",
    "MAX_CANONICAL_PAYLOAD_BYTES",
    "MAX_CAPTURE_BYTES",
    "MAX_CAPTURE_RECORDS",
    "MAX_MARKER_BYTES",
    "MAX_RUN_ID_BYTES",
    "CaptureSession",
    "canonical_json_bytes",
    "encode_marker",
    "marker_payload",
    "new_capture_session",
    "open_receipt",
    "parse_marker",
    "payload_hmac",
    "receipt_projection",
    "row_aad",
    "row_hmac",
    "seal_receipt",
    "verify_row_hmac",
]
