"""Domain-separated integrity for local approval authority outside policy rows."""

from __future__ import annotations

import hashlib
import hmac
import json
from collections.abc import Mapping

from .policy_integrity import PolicyIntegrityVerificationResult

LOCAL_AUTHORITY_INTEGRITY_VERSION = 1
LOCAL_AUTHORITY_INTEGRITY_MAC_ALGORITHM = "hmac-sha256"
_LOCAL_AUTHORITY_INTEGRITY_DOMAIN = b"hol-guard.local-authority-integrity.v1"


def sign_local_authority_payload(
    payload: Mapping[str, object],
    *,
    key: bytes,
    key_id: str,
    purpose: str,
    signed_at: str,
) -> dict[str, object]:
    """Sign a local authority payload with a purpose-specific derived key."""

    canonical_payload = _canonical_local_authority_payload(
        payload,
        purpose=purpose,
        signed_at=signed_at,
        integrity_version=LOCAL_AUTHORITY_INTEGRITY_VERSION,
    )
    return {
        "integrity_version": LOCAL_AUTHORITY_INTEGRITY_VERSION,
        "payload_hash": hashlib.sha256(canonical_payload).hexdigest(),
        "payload_mac": hmac.new(
            _purpose_key(key, purpose=purpose),
            canonical_payload,
            hashlib.sha256,
        ).hexdigest(),
        "integrity_key_id": key_id,
        "signed_at": signed_at,
    }


def verify_local_authority_payload(
    payload: Mapping[str, object],
    integrity: Mapping[str, object],
    *,
    key: bytes | None,
    key_id: str | None,
    purpose: str,
) -> PolicyIntegrityVerificationResult:
    """Verify purpose-bound local authority without creating key material."""

    version = _int_or_none(_mapping_value(integrity, "integrity_version"))
    stored_payload_hash = _string_or_none(_mapping_value(integrity, "payload_hash"))
    stored_payload_mac = _string_or_none(_mapping_value(integrity, "payload_mac"))
    stored_key_id = _string_or_none(_mapping_value(integrity, "integrity_key_id"))
    signed_at = _string_or_none(_mapping_value(integrity, "signed_at"))
    if (
        version is None
        or stored_payload_hash is None
        or stored_payload_mac is None
        or stored_key_id is None
        or signed_at is None
    ):
        return PolicyIntegrityVerificationResult(
            status="missing_integrity",
            payload_hash=stored_payload_hash,
            key_id=stored_key_id,
            message="local_authority_integrity_metadata_missing",
        )
    if version != LOCAL_AUTHORITY_INTEGRITY_VERSION:
        return PolicyIntegrityVerificationResult(
            status="tampered",
            payload_hash=stored_payload_hash,
            key_id=stored_key_id,
            message="local_authority_integrity_version_unsupported",
        )
    if key is None or key_id is None or not _constant_time_text_equal(stored_key_id, key_id):
        return PolicyIntegrityVerificationResult(
            status="unknown_key",
            payload_hash=stored_payload_hash,
            key_id=stored_key_id,
            message="local_authority_integrity_key_unavailable",
        )

    try:
        canonical_payload = _canonical_local_authority_payload(
            payload,
            purpose=purpose,
            signed_at=signed_at,
            integrity_version=version,
        )
    except (TypeError, UnicodeError, ValueError):
        return PolicyIntegrityVerificationResult(
            status="tampered",
            payload_hash=stored_payload_hash,
            key_id=stored_key_id,
            message="local_authority_integrity_payload_invalid",
        )
    computed_payload_hash = hashlib.sha256(canonical_payload).hexdigest()
    if not _constant_time_text_equal(stored_payload_hash, computed_payload_hash):
        return PolicyIntegrityVerificationResult(
            status="tampered",
            payload_hash=computed_payload_hash,
            key_id=stored_key_id,
            message="local_authority_integrity_payload_hash_mismatch",
        )
    computed_payload_mac = hmac.new(
        _purpose_key(key, purpose=purpose),
        canonical_payload,
        hashlib.sha256,
    ).hexdigest()
    if not _constant_time_text_equal(stored_payload_mac, computed_payload_mac):
        return PolicyIntegrityVerificationResult(
            status="tampered",
            payload_hash=computed_payload_hash,
            key_id=stored_key_id,
            message="local_authority_integrity_mac_mismatch",
        )
    return PolicyIntegrityVerificationResult(
        status="valid",
        payload_hash=computed_payload_hash,
        key_id=stored_key_id,
        message=LOCAL_AUTHORITY_INTEGRITY_MAC_ALGORITHM,
    )


def _canonical_local_authority_payload(
    payload: Mapping[str, object],
    *,
    purpose: str,
    signed_at: str,
    integrity_version: int,
) -> bytes:
    envelope = {
        "domain": _LOCAL_AUTHORITY_INTEGRITY_DOMAIN.decode("ascii"),
        "integrity_version": integrity_version,
        "payload": dict(payload),
        "purpose": purpose,
        "signed_at": signed_at,
    }
    return json.dumps(envelope, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _purpose_key(key: bytes, *, purpose: str) -> bytes:
    return hmac.new(
        key,
        _LOCAL_AUTHORITY_INTEGRITY_DOMAIN + b"\0" + purpose.encode("utf-8"),
        hashlib.sha256,
    ).digest()


def _string_or_none(value: object) -> str | None:
    return value if isinstance(value, str) and value else None


def _int_or_none(value: object) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _mapping_value(mapping: Mapping[str, object], key: str) -> object:
    try:
        return mapping[key]
    except KeyError:
        return None


def _constant_time_text_equal(left: str, right: str) -> bool:
    return hmac.compare_digest(left.encode("utf-8"), right.encode("utf-8"))
