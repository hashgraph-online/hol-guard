"""Local policy row integrity helpers."""

from __future__ import annotations

import hashlib
import hmac
import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Literal

POLICY_INTEGRITY_VERSION = 2
POLICY_INTEGRITY_MAC_ALGORITHM = "hmac-sha256"
_LEGACY_POLICY_INTEGRITY_VERSION = 1
_SUPPORTED_POLICY_INTEGRITY_VERSIONS = frozenset({_LEGACY_POLICY_INTEGRITY_VERSION, POLICY_INTEGRITY_VERSION})
REMOTE_POLICY_SOURCES = frozenset({"cloud-sync", "team-policy", "policy-bundle"})

PolicyIntegrityStatus = Literal[
    "valid",
    "missing_integrity",
    "tampered",
    "unknown_key",
    "rollback_detected",
    "degraded_mode",
]


@dataclass(frozen=True, slots=True)
class PolicyIntegrityVerificationResult:
    status: PolicyIntegrityStatus
    payload_hash: str | None = None
    key_id: str | None = None
    message: str | None = None


def is_remote_policy_source(source: str | None) -> bool:
    return isinstance(source, str) and source in REMOTE_POLICY_SOURCES


def canonical_policy_payload(
    row: Mapping[str, object],
    *,
    integrity_version: int | None = None,
) -> bytes:
    resolved_version = (
        integrity_version
        if integrity_version is not None
        else (_int_or_none(_mapping_value(row, "integrity_version")) or POLICY_INTEGRITY_VERSION)
    )
    payload: dict[str, object] = {
        "action": _string_or_none(_mapping_value(row, "action")),
        "artifact_hash": _string_or_none(_mapping_value(row, "artifact_hash")),
        "artifact_id": _string_or_none(_mapping_value(row, "artifact_id")),
        "expires_at": _string_or_none(_mapping_value(row, "expires_at")),
        "harness": _string_or_none(_mapping_value(row, "harness")),
        "integrity_version": resolved_version,
        "publisher": _string_or_none(_mapping_value(row, "publisher")),
        "scope": _string_or_none(_mapping_value(row, "scope")),
        "source": _string_or_none(_mapping_value(row, "source")),
        "updated_at": _string_or_none(_mapping_value(row, "updated_at")),
        "workspace": _string_or_none(_mapping_value(row, "workspace")),
    }
    if resolved_version == POLICY_INTEGRITY_VERSION:
        payload["decision_id"] = _int_or_none(_mapping_value(row, "decision_id"))
        payload["integrity_generation"] = _int_or_none(_mapping_value(row, "integrity_generation"))
        payload["owner"] = _string_or_none(_mapping_value(row, "owner"))
        payload["reason"] = _string_or_none(_mapping_value(row, "reason"))
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def sign_local_policy_row(
    row: Mapping[str, object],
    key: bytes,
    *,
    key_id: str,
    signed_at: str,
    generation: int,
) -> dict[str, object]:
    signing_row = dict(row)
    signing_row["integrity_generation"] = generation
    payload = canonical_policy_payload(signing_row, integrity_version=POLICY_INTEGRITY_VERSION)
    payload_hash = hashlib.sha256(payload).hexdigest()
    payload_mac = hmac.new(key, payload, hashlib.sha256).hexdigest()
    return {
        "integrity_version": POLICY_INTEGRITY_VERSION,
        "integrity_generation": generation,
        "payload_hash": payload_hash,
        "payload_mac": payload_mac,
        "integrity_key_id": key_id,
        "signed_at": signed_at,
    }


def verify_local_policy_row(
    row: Mapping[str, object],
    *,
    key: bytes | None,
    key_id: str | None,
    degraded_mode: bool = False,
    trusted_generation: int | None = None,
) -> PolicyIntegrityVerificationResult:
    stored_key_id = _string_or_none(_mapping_value(row, "integrity_key_id"))
    stored_payload_hash = _string_or_none(_mapping_value(row, "payload_hash"))
    stored_payload_mac = _string_or_none(_mapping_value(row, "payload_mac"))
    stored_signed_at = _string_or_none(_mapping_value(row, "signed_at"))
    version = _int_or_none(_mapping_value(row, "integrity_version"))

    if degraded_mode:
        return PolicyIntegrityVerificationResult(
            status="degraded_mode",
            payload_hash=stored_payload_hash,
            key_id=stored_key_id,
            message="policy_integrity_backend_unavailable",
        )
    if (
        version is None
        or stored_key_id is None
        or stored_payload_hash is None
        or stored_payload_mac is None
        or stored_signed_at is None
    ):
        return PolicyIntegrityVerificationResult(
            status="missing_integrity",
            payload_hash=stored_payload_hash,
            key_id=stored_key_id,
            message="policy_integrity_metadata_missing",
        )
    if version not in _SUPPORTED_POLICY_INTEGRITY_VERSIONS:
        return PolicyIntegrityVerificationResult(
            status="tampered",
            payload_hash=stored_payload_hash,
            key_id=stored_key_id,
            message="policy_integrity_version_unsupported",
        )
    if key is None or key_id is None or stored_key_id != key_id:
        return PolicyIntegrityVerificationResult(
            status="unknown_key",
            payload_hash=stored_payload_hash,
            key_id=stored_key_id,
            message="policy_integrity_key_unavailable",
        )

    payload = canonical_policy_payload(row, integrity_version=version)
    computed_payload_hash = hashlib.sha256(payload).hexdigest()
    if not hmac.compare_digest(stored_payload_hash, computed_payload_hash):
        return PolicyIntegrityVerificationResult(
            status="tampered",
            payload_hash=computed_payload_hash,
            key_id=stored_key_id,
            message="policy_integrity_payload_hash_mismatch",
        )

    computed_payload_mac = hmac.new(key, payload, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(stored_payload_mac, computed_payload_mac):
        return PolicyIntegrityVerificationResult(
            status="tampered",
            payload_hash=computed_payload_hash,
            key_id=stored_key_id,
            message="policy_integrity_mac_mismatch",
        )
    if version == POLICY_INTEGRITY_VERSION and trusted_generation is not None:
        stored_generation = _int_or_none(_mapping_value(row, "integrity_generation"))
        if stored_generation != trusted_generation:
            return PolicyIntegrityVerificationResult(
                status="rollback_detected",
                payload_hash=computed_payload_hash,
                key_id=stored_key_id,
                message="policy_integrity_generation_rollback",
            )
    return PolicyIntegrityVerificationResult(
        status="valid",
        payload_hash=computed_payload_hash,
        key_id=stored_key_id,
        message=POLICY_INTEGRITY_MAC_ALGORITHM,
    )


def _string_or_none(value: object) -> str | None:
    return value if isinstance(value, str) and value else None


def _int_or_none(value: object) -> int | None:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        stripped = value.strip()
        if stripped.isdigit():
            return int(stripped)
    return None


def _mapping_value(row: Mapping[str, object], key: str) -> object:
    try:
        return row[key]
    except KeyError:
        return None
