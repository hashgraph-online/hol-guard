"""Frozen ``protection-lease.v1`` challenge and signature contract."""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass
from datetime import datetime, timedelta

from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature

from .contracts import LOCAL_INTEGRITY_SNAPSHOT_SCHEMA_VERSION
from .health_lease_contract import (
    MAX_LEASE_BYTES,
    MAX_UINT64,
    P256_ORDER,
    SIGNATURE_ALGORITHM,
    _exact_keys,
    _match,
    _parse_timestamp,
    _safe_id,
    _strict_json,
    canonical_json_bytes,
    canonical_timestamp,
)

PROTECTION_LEASE_SCHEMA = "protection-lease.v1"
_HEX_32 = __import__("re").compile(r"[0-9a-f]{32}\Z")
_HEX_64 = __import__("re").compile(r"[0-9a-f]{64}\Z")
_KEY_ID = __import__("re").compile(r"[A-Za-z0-9_-]{43}\Z")
_SNAPSHOT_TIMESTAMP = __import__("re").compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z\Z")
_PROTECTION_CLAIM_KEYS = {
    "workspaceId",
    "deviceId",
    "machineInstallationId",
    "installationGeneration",
    "sequence",
    "issuedAt",
    "validForSeconds",
    "snapshotSchemaVersion",
    "snapshotDigest",
    "previousLeaseDigest",
    "signingKeyId",
    "challenge",
}
_CHALLENGE_KEYS = {"challengeId", "issuedAt", "nonce", "validForSeconds"}


@dataclass(frozen=True, slots=True)
class ProtectionLeaseChallenge:
    challenge_id: str
    issued_at: str
    nonce: str
    valid_for_seconds: int

    def to_dict(self) -> dict[str, object]:
        return {
            "challengeId": self.challenge_id,
            "issuedAt": self.issued_at,
            "nonce": self.nonce,
            "validForSeconds": self.valid_for_seconds,
        }

    @classmethod
    def parse(cls, raw: object) -> ProtectionLeaseChallenge:
        import re

        if not isinstance(raw, dict):
            raise ValueError("health_lease_challenge_invalid")
        _exact_keys(raw, _CHALLENGE_KEYS, "health_lease_challenge_invalid")
        issued_at = raw.get("issuedAt")
        nonce = raw.get("nonce")
        valid_for_seconds = raw.get("validForSeconds")
        if (
            not isinstance(issued_at, str)
            or _SNAPSHOT_TIMESTAMP.fullmatch(issued_at) is None
            or not isinstance(nonce, str)
            or re.fullmatch(r"[A-Za-z0-9_-]{32,128}", nonce) is None
            or not isinstance(valid_for_seconds, int)
            or isinstance(valid_for_seconds, bool)
            or not 30 <= valid_for_seconds <= 300
        ):
            raise ValueError("health_lease_challenge_invalid")
        try:
            parsed = datetime.fromisoformat(f"{issued_at[:-1]}+00:00")
        except ValueError as exc:
            raise ValueError("health_lease_challenge_invalid") from exc
        if parsed.tzinfo is None:
            raise ValueError("health_lease_challenge_invalid")
        return cls(_safe_id(raw.get("challengeId")), issued_at, nonce, valid_for_seconds)


@dataclass(frozen=True, slots=True)
class ProtectionLeaseClaims:
    workspace_id: str
    device_id: str
    machine_installation_id: str
    installation_generation: str
    sequence: int
    issued_at: str
    valid_for_seconds: int
    snapshot_schema_version: str
    snapshot_digest: str
    previous_lease_digest: str | None
    signing_key_id: str
    challenge: ProtectionLeaseChallenge | None

    @property
    def lease_expires_at(self) -> str:
        return canonical_timestamp(_parse_timestamp(self.issued_at) + timedelta(seconds=self.valid_for_seconds))

    @property
    def previous_lease_key_id(self) -> None:
        return None

    def to_dict(self) -> dict[str, object]:
        return {
            "workspaceId": self.workspace_id,
            "deviceId": self.device_id,
            "machineInstallationId": self.machine_installation_id,
            "installationGeneration": self.installation_generation,
            "sequence": self.sequence,
            "issuedAt": self.issued_at,
            "validForSeconds": self.valid_for_seconds,
            "snapshotSchemaVersion": self.snapshot_schema_version,
            "snapshotDigest": self.snapshot_digest,
            "previousLeaseDigest": self.previous_lease_digest,
            "signingKeyId": self.signing_key_id,
            "challenge": self.challenge.to_dict() if self.challenge is not None else None,
        }

    @classmethod
    def parse(cls, raw: object) -> ProtectionLeaseClaims:
        if not isinstance(raw, dict):
            raise ValueError("health_lease_invalid")
        _exact_keys(raw, _PROTECTION_CLAIM_KEYS)
        sequence = raw.get("sequence")
        duration = raw.get("validForSeconds")
        if (
            not isinstance(sequence, int)
            or isinstance(sequence, bool)
            or not 1 <= sequence <= MAX_UINT64
            or not isinstance(duration, int)
            or isinstance(duration, bool)
            or not 180 <= duration <= 1800
        ):
            raise ValueError("health_lease_invalid")
        previous = raw.get("previousLeaseDigest")
        if (sequence == 1 and previous is not None) or (
            sequence > 1 and (not isinstance(previous, str) or _HEX_64.fullmatch(previous) is None)
        ):
            raise ValueError("health_lease_invalid")
        issued_at = canonical_timestamp(_parse_timestamp(raw.get("issuedAt")))
        challenge_raw = raw.get("challenge")
        challenge = None if challenge_raw is None else ProtectionLeaseChallenge.parse(challenge_raw)
        if raw.get("snapshotSchemaVersion") != LOCAL_INTEGRITY_SNAPSHOT_SCHEMA_VERSION:
            raise ValueError("health_lease_invalid")
        if challenge is not None:
            challenge_issued = datetime.fromisoformat(f"{challenge.issued_at[:-1]}+00:00")
            lease_issued = _parse_timestamp(issued_at)
            if not challenge_issued <= lease_issued < challenge_issued + timedelta(seconds=challenge.valid_for_seconds):
                raise ValueError("health_lease_challenge_invalid")
        return cls(
            _safe_id(raw.get("workspaceId")),
            _safe_id(raw.get("deviceId")),
            _match(raw.get("machineInstallationId"), _HEX_32),
            _match(raw.get("installationGeneration"), _HEX_32),
            sequence,
            issued_at,
            duration,
            LOCAL_INTEGRITY_SNAPSHOT_SCHEMA_VERSION,
            _match(raw.get("snapshotDigest"), _HEX_64),
            None if previous is None else previous,
            _match(raw.get("signingKeyId"), _KEY_ID),
            challenge,
        )

    def signing_payload(self) -> bytes:
        return canonical_json_bytes({"claims": self.to_dict(), "schemaVersion": PROTECTION_LEASE_SCHEMA})


def _canonical_signature(signature: bytes) -> bytes:
    try:
        r, s = decode_dss_signature(signature)
    except ValueError as exc:
        raise ValueError("health_lease_invalid") from exc
    if not 1 <= r < P256_ORDER or not 1 <= s < P256_ORDER or encode_dss_signature(r, s) != signature:
        raise ValueError("health_lease_invalid")
    return encode_dss_signature(r, min(s, P256_ORDER - s))


@dataclass(frozen=True, slots=True)
class SignedProtectionLease:
    claims: ProtectionLeaseClaims
    signature: bytes

    def to_dict(self) -> dict[str, object]:
        canonical = _canonical_signature(self.signature)
        r, s = decode_dss_signature(canonical)
        value = base64.b64encode(r.to_bytes(32, "big") + s.to_bytes(32, "big")).decode("ascii")
        return {
            "schemaVersion": PROTECTION_LEASE_SCHEMA,
            "claims": self.claims.to_dict(),
            "signature": {
                "algorithm": SIGNATURE_ALGORITHM,
                "keyId": self.claims.signing_key_id,
                "value": value,
            },
        }

    def canonical_bytes(self) -> bytes:
        payload = canonical_json_bytes(self.to_dict())
        if len(payload) > MAX_LEASE_BYTES:
            raise ValueError("health_lease_invalid")
        return payload

    @property
    def digest(self) -> str:
        return hashlib.sha256(self.canonical_bytes()).hexdigest()

    @classmethod
    def parse(cls, payload: bytes) -> SignedProtectionLease:
        raw = _strict_json(payload, maximum=MAX_LEASE_BYTES, reason="health_lease_invalid")
        _exact_keys(raw, {"schemaVersion", "claims", "signature"})
        if raw.get("schemaVersion") != PROTECTION_LEASE_SCHEMA:
            raise ValueError("health_lease_invalid")
        claims = ProtectionLeaseClaims.parse(raw.get("claims"))
        signature = raw.get("signature")
        if not isinstance(signature, dict):
            raise ValueError("health_lease_invalid")
        _exact_keys(signature, {"algorithm", "keyId", "value"})
        value = signature.get("value")
        if (
            signature.get("algorithm") != SIGNATURE_ALGORITHM
            or signature.get("keyId") != claims.signing_key_id
            or not isinstance(value, str)
            or len(value) > 128
        ):
            raise ValueError("health_lease_invalid")
        try:
            raw_signature = base64.b64decode(value, validate=True)
            if len(raw_signature) != 64:
                raise ValueError
            r = int.from_bytes(raw_signature[:32], "big")
            s = int.from_bytes(raw_signature[32:], "big")
            if not 1 <= r < P256_ORDER or not 1 <= s <= P256_ORDER // 2:
                raise ValueError
            parsed = encode_dss_signature(r, s)
        except (ValueError, TypeError) as exc:
            raise ValueError("health_lease_invalid") from exc
        if base64.b64encode(raw_signature).decode("ascii") != value:
            raise ValueError("health_lease_invalid")
        return cls(claims, parsed)


__all__ = ["PROTECTION_LEASE_SCHEMA", "ProtectionLeaseChallenge", "ProtectionLeaseClaims", "SignedProtectionLease"]
