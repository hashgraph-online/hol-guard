"""Frozen ``protection-lease.v1`` challenge and signature contract.

The native runtime parses challenges, claims and signed leases; this module
keeps the dataclasses that sign and serialize them.
"""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature

from .health_lease_contract import (
    MAX_LEASE_BYTES,
    P256_ORDER,
    SIGNATURE_ALGORITHM,
    canonical_json_bytes,
    canonical_timestamp,
    check_value,
    parse_payload,
)

PROTECTION_LEASE_SCHEMA = "protection-lease.v1"
MIN_PROTECTION_LEASE_SECONDS = 180
MAX_PROTECTION_LEASE_SECONDS = 1800


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
        return cls.from_contract(check_value("protection-challenge", raw, "health_lease_challenge_invalid"))

    @classmethod
    def from_contract(cls, raw: dict[str, Any]) -> ProtectionLeaseChallenge:
        """A challenge the runtime already accepted."""

        return cls(raw["challengeId"], raw["issuedAt"], raw["nonce"], raw["validForSeconds"])


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
        issued = datetime.strptime(self.issued_at, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        return canonical_timestamp(issued + timedelta(seconds=self.valid_for_seconds))

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
        return cls.from_contract(check_value("protection-claims", raw))

    @classmethod
    def from_contract(cls, raw: dict[str, Any]) -> ProtectionLeaseClaims:
        """Claims the runtime already accepted."""

        challenge = raw["challenge"]
        return cls(
            raw["workspaceId"],
            raw["deviceId"],
            raw["machineInstallationId"],
            raw["installationGeneration"],
            raw["sequence"],
            raw["issuedAt"],
            raw["validForSeconds"],
            raw["snapshotSchemaVersion"],
            raw["snapshotDigest"],
            raw["previousLeaseDigest"],
            raw["signingKeyId"],
            None if challenge is None else ProtectionLeaseChallenge.from_contract(challenge),
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
        claims, signature, _ = parse_payload(
            "protection-lease", payload, maximum=MAX_LEASE_BYTES, reason="health_lease_invalid"
        )
        return cls.from_contract(claims, signature)

    @classmethod
    def from_contract(cls, claims: dict[str, Any], signature: bytes) -> SignedProtectionLease:
        """A lease the runtime already accepted, with its signature as DER."""

        return cls(ProtectionLeaseClaims.from_contract(claims), signature)


__all__ = [
    "MAX_PROTECTION_LEASE_SECONDS",
    "MIN_PROTECTION_LEASE_SECONDS",
    "PROTECTION_LEASE_SCHEMA",
    "ProtectionLeaseChallenge",
    "ProtectionLeaseClaims",
    "SignedProtectionLease",
]
