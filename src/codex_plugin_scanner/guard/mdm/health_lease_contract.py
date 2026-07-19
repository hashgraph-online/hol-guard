"""Strict, versioned contract for machine health leases."""

from __future__ import annotations

import base64
import hashlib
import importlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Final, Protocol, cast

from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature

from .contracts import LOCAL_INTEGRITY_SNAPSHOT_SCHEMA_VERSION


class LeaseClaims(Protocol):
    @property
    def workspace_id(self) -> str: ...
    @property
    def device_id(self) -> str: ...
    @property
    def machine_installation_id(self) -> str: ...
    @property
    def installation_generation(self) -> str: ...
    @property
    def sequence(self) -> int: ...
    @property
    def issued_at(self) -> str: ...
    @property
    def lease_expires_at(self) -> str: ...
    @property
    def snapshot_schema_version(self) -> str: ...
    @property
    def snapshot_digest(self) -> str: ...
    @property
    def previous_lease_digest(self) -> str | None: ...
    @property
    def signing_key_id(self) -> str: ...


class ProtectionLease(Protocol):
    @property
    def claims(self) -> LeaseClaims: ...

    @property
    def signature(self) -> bytes: ...

    @property
    def digest(self) -> str: ...

    def to_dict(self) -> dict[str, object]: ...

    def canonical_bytes(self) -> bytes: ...

    @classmethod
    def parse(cls, payload: bytes) -> ProtectionLease: ...


HEALTH_LEASE_SCHEMA: Final = "hol-guard-health-lease.v1"
HEALTH_LEASE_OUTBOX_SCHEMA: Final = "hol-guard-health-lease-outbox.v1"
HEALTH_LEASE_SIGNING_DOMAIN: Final = b"HOL-GUARD-HEALTH-LEASE-V1\x00"
SIGNATURE_ALGORITHM: Final = "ecdsa-p256-sha256"
SIGNATURE_ENCODING: Final = "asn1-der"
MAX_LEASE_BYTES: Final = 32 * 1024
MAX_SNAPSHOT_BYTES: Final = 256 * 1024
MAX_OUTBOX_BYTES: Final = 4 * ((MAX_SNAPSHOT_BYTES + 2) // 3) + MAX_LEASE_BYTES + 4096
MAX_LEASE_SECONDS: Final = 3600
MAX_UINT64: Final = (1 << 64) - 1
P256_ORDER: Final = int("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)

_SAFE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_HEX_32 = re.compile(r"[0-9a-f]{32}\Z")
_HEX_64 = re.compile(r"[0-9a-f]{64}\Z")
_KEY_ID = re.compile(r"[A-Za-z0-9_-]{43}\Z")
_TIMESTAMP = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z")
_CLAIM_KEYS = {
    "schemaVersion",
    "workspaceId",
    "deviceId",
    "machineInstallationId",
    "installationGeneration",
    "sequence",
    "issuedAt",
    "leaseExpiresAt",
    "snapshotSchemaVersion",
    "snapshotDigest",
    "previousLeaseDigest",
    "previousLeaseKeyId",
    "signingKeyId",
}


def canonical_json_bytes(payload: dict[str, object]) -> bytes:
    try:
        encoded = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise ValueError("health_lease_json_invalid") from exc
    return encoded.encode("utf-8")


def canonical_timestamp(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("health_lease_invalid")
    normalized = value.astimezone(timezone.utc).replace(microsecond=0)
    return normalized.strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_timestamp(value: object) -> datetime:
    if not isinstance(value, str) or _TIMESTAMP.fullmatch(value) is None:
        raise ValueError("health_lease_invalid")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise ValueError("health_lease_invalid") from exc


def _strict_json(payload: bytes, *, maximum: int, reason: str) -> dict[str, object]:
    if not payload or len(payload) > maximum:
        raise ValueError(reason)
    try:
        decoded = payload.decode("utf-8")
        raw = json.loads(decoded, parse_constant=_reject_json_constant)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(reason) from exc
    if not isinstance(raw, dict) or canonical_json_bytes(raw) != payload:
        raise ValueError(reason)
    return raw


def _reject_json_constant(_value: str) -> None:
    raise ValueError("health_lease_json_invalid")


def _exact_keys(raw: dict[str, object], expected: set[str], reason: str = "health_lease_invalid") -> None:
    if set(raw) != expected:
        raise ValueError(reason)


def _safe_id(value: object) -> str:
    if not isinstance(value, str) or _SAFE_ID.fullmatch(value) is None:
        raise ValueError("health_lease_invalid")
    return value


def _match(value: object, pattern: re.Pattern[str]) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise ValueError("health_lease_invalid")
    return value


def _bounded_string(value: object, *, maximum: int, nullable: bool = False) -> str | None:
    if value is None and nullable:
        return None
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > maximum:
        raise ValueError("health_lease_outbox_invalid")
    return value


def _optional_uint64(value: object) -> int | None:
    if value is None:
        return None
    if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= MAX_UINT64:
        raise ValueError("health_lease_outbox_invalid")
    return value


@dataclass(frozen=True, slots=True)
class HealthLeaseBinding:
    workspace_id: str
    device_id: str

    def __post_init__(self) -> None:
        _safe_id(self.workspace_id)
        _safe_id(self.device_id)


@dataclass(frozen=True, slots=True)
class HealthLeaseClaims:
    workspace_id: str
    device_id: str
    machine_installation_id: str
    installation_generation: str
    sequence: int
    issued_at: str
    lease_expires_at: str
    snapshot_schema_version: str
    snapshot_digest: str
    previous_lease_digest: str | None
    previous_lease_key_id: str | None
    signing_key_id: str

    def to_dict(self) -> dict[str, object]:
        return {
            "schemaVersion": HEALTH_LEASE_SCHEMA,
            "workspaceId": self.workspace_id,
            "deviceId": self.device_id,
            "machineInstallationId": self.machine_installation_id,
            "installationGeneration": self.installation_generation,
            "sequence": self.sequence,
            "issuedAt": self.issued_at,
            "leaseExpiresAt": self.lease_expires_at,
            "snapshotSchemaVersion": self.snapshot_schema_version,
            "snapshotDigest": self.snapshot_digest,
            "previousLeaseDigest": self.previous_lease_digest,
            "previousLeaseKeyId": self.previous_lease_key_id,
            "signingKeyId": self.signing_key_id,
        }

    @classmethod
    def parse(cls, raw: object) -> HealthLeaseClaims:
        if not isinstance(raw, dict):
            raise ValueError("health_lease_invalid")
        _exact_keys(raw, _CLAIM_KEYS)
        if raw.get("schemaVersion") != HEALTH_LEASE_SCHEMA:
            raise ValueError("health_lease_invalid")
        sequence = raw.get("sequence")
        if not isinstance(sequence, int) or isinstance(sequence, bool) or not 1 <= sequence <= MAX_UINT64:
            raise ValueError("health_lease_invalid")
        previous_digest = raw.get("previousLeaseDigest")
        previous_key = raw.get("previousLeaseKeyId")
        if sequence == 1:
            if previous_digest is not None or previous_key is not None:
                raise ValueError("health_lease_invalid")
        elif previous_digest is None or previous_key is None:
            raise ValueError("health_lease_invalid")
        issued = _parse_timestamp(raw.get("issuedAt"))
        expires = _parse_timestamp(raw.get("leaseExpiresAt"))
        duration = (expires - issued).total_seconds()
        if duration <= 0 or duration > MAX_LEASE_SECONDS:
            raise ValueError("health_lease_invalid")
        if raw.get("snapshotSchemaVersion") != LOCAL_INTEGRITY_SNAPSHOT_SCHEMA_VERSION:
            raise ValueError("health_lease_invalid")
        return cls(
            _safe_id(raw.get("workspaceId")),
            _safe_id(raw.get("deviceId")),
            _match(raw.get("machineInstallationId"), _HEX_32),
            _match(raw.get("installationGeneration"), _HEX_32),
            sequence,
            canonical_timestamp(issued),
            canonical_timestamp(expires),
            LOCAL_INTEGRITY_SNAPSHOT_SCHEMA_VERSION,
            _match(raw.get("snapshotDigest"), _HEX_64),
            None if previous_digest is None else _match(previous_digest, _HEX_64),
            None if previous_key is None else _match(previous_key, _KEY_ID),
            _match(raw.get("signingKeyId"), _KEY_ID),
        )

    def signing_payload(self) -> bytes:
        return HEALTH_LEASE_SIGNING_DOMAIN + canonical_json_bytes(self.to_dict())


def _canonical_ecdsa_signature(signature: bytes) -> bytes:
    try:
        r, s = decode_dss_signature(signature)
    except ValueError as exc:
        raise ValueError("health_lease_invalid") from exc
    if not 1 <= r < P256_ORDER or not 1 <= s < P256_ORDER or encode_dss_signature(r, s) != signature:
        raise ValueError("health_lease_invalid")
    if s <= P256_ORDER // 2:
        return signature
    return encode_dss_signature(r, P256_ORDER - s)


@dataclass(frozen=True, slots=True)
class SignedHealthLease:
    claims: HealthLeaseClaims
    signature: bytes

    def to_dict(self) -> dict[str, object]:
        signature = _canonical_ecdsa_signature(self.signature)
        return {
            "claims": self.claims.to_dict(),
            "signature": {
                "algorithm": SIGNATURE_ALGORITHM,
                "encoding": SIGNATURE_ENCODING,
                "value": base64.b64encode(signature).decode("ascii"),
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
    def parse(cls, payload: bytes) -> SignedHealthLease:
        raw = _strict_json(payload, maximum=MAX_LEASE_BYTES, reason="health_lease_invalid")
        _exact_keys(raw, {"claims", "signature"})
        signature_raw = raw.get("signature")
        if not isinstance(signature_raw, dict):
            raise ValueError("health_lease_invalid")
        _exact_keys(signature_raw, {"algorithm", "encoding", "value"})
        if signature_raw.get("algorithm") != SIGNATURE_ALGORITHM or signature_raw.get("encoding") != SIGNATURE_ENCODING:
            raise ValueError("health_lease_invalid")
        value = signature_raw.get("value")
        if not isinstance(value, str) or len(value) > 128:
            raise ValueError("health_lease_invalid")
        try:
            signature = base64.b64decode(value, validate=True)
            canonical_signature = _canonical_ecdsa_signature(signature)
        except (ValueError, TypeError) as exc:
            raise ValueError("health_lease_invalid") from exc
        if canonical_signature != signature or base64.b64encode(signature).decode("ascii") != value:
            raise ValueError("health_lease_invalid")
        return cls(HealthLeaseClaims.parse(raw.get("claims")), signature)


@dataclass(frozen=True, slots=True)
class HealthLeaseOutbox:
    lease: SignedHealthLease | ProtectionLease
    snapshot_bytes: bytes

    def to_dict(self) -> dict[str, object]:
        return {
            "schemaVersion": HEALTH_LEASE_OUTBOX_SCHEMA,
            "lease": self.lease.to_dict(),
            "leaseDigest": self.lease.digest,
            "snapshot": base64.b64encode(self.snapshot_bytes).decode("ascii"),
        }

    def canonical_bytes(self) -> bytes:
        _validate_snapshot_binding(self.snapshot_bytes, self.lease.claims)
        payload = canonical_json_bytes(self.to_dict())
        if len(payload) > MAX_OUTBOX_BYTES:
            raise ValueError("health_lease_outbox_invalid")
        return payload

    @classmethod
    def parse(cls, payload: bytes) -> HealthLeaseOutbox:
        raw = _strict_json(payload, maximum=MAX_OUTBOX_BYTES, reason="health_lease_outbox_invalid")
        _exact_keys(raw, {"schemaVersion", "lease", "leaseDigest", "snapshot"}, "health_lease_outbox_invalid")
        if raw.get("schemaVersion") != HEALTH_LEASE_OUTBOX_SCHEMA:
            raise ValueError("health_lease_outbox_invalid")
        lease_raw = raw.get("lease")
        if not isinstance(lease_raw, dict):
            raise ValueError("health_lease_outbox_invalid")
        if lease_raw.get("schemaVersion") == "protection-lease.v1":
            module = importlib.import_module(".protection_lease_contract", __package__)
            lease_type = cast(type[ProtectionLease], module.SignedProtectionLease)
            lease: SignedHealthLease | ProtectionLease = lease_type.parse(canonical_json_bytes(lease_raw))
        else:
            lease = SignedHealthLease.parse(canonical_json_bytes(lease_raw))
        snapshot_raw = raw.get("snapshot")
        if not isinstance(snapshot_raw, str):
            raise ValueError("health_lease_outbox_invalid")
        try:
            snapshot = base64.b64decode(snapshot_raw, validate=True)
        except ValueError as exc:
            raise ValueError("health_lease_outbox_invalid") from exc
        snapshot_digest = hashlib.sha256(snapshot).hexdigest()
        if not snapshot or len(snapshot) > MAX_SNAPSHOT_BYTES or snapshot_digest != lease.claims.snapshot_digest:
            raise ValueError("health_lease_outbox_invalid")
        if raw.get("leaseDigest") != lease.digest:
            raise ValueError("health_lease_outbox_invalid")
        outbox = cls(lease, snapshot)
        _validate_snapshot_binding(snapshot, lease.claims)
        return outbox


def _validate_snapshot_binding(snapshot: bytes, claims: LeaseClaims) -> None:
    from .health_snapshot_validation import validate_health_snapshot_binding

    validate_health_snapshot_binding(snapshot, claims)


__all__ = [
    "HEALTH_LEASE_SIGNING_DOMAIN",
    "HealthLeaseBinding",
    "HealthLeaseClaims",
    "HealthLeaseOutbox",
    "SignedHealthLease",
    "canonical_json_bytes",
    "canonical_timestamp",
]
