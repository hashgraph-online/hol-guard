"""Strict, versioned contract for machine health leases."""

from __future__ import annotations

import base64
import hashlib
import json
import math
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Final, get_args

from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature

from .contracts import (
    LOCAL_INTEGRITY_SNAPSHOT_SCHEMA_VERSION,
    AssuranceLevel,
    InstallOwner,
    IntegrityReasonCode,
    IntegrityState,
    KeyProtectionLevel,
    RemediationClass,
    SupervisorState,
)

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
_SNAPSHOT_KEYS = {
    "schemaVersion",
    "generatedAt",
    "scope",
    "healthy",
    "assuranceLevel",
    "installOwner",
    "platform",
    "architecture",
    "identifiers",
    "product",
    "components",
    "harnessCoverage",
    "continuity",
    "reasonCodes",
    "remediationClass",
}
_IDENTIFIER_KEYS = {"workspaceId", "deviceId", "machineInstallationId", "installationGeneration"}
_PRODUCT_KEYS = {"version", "buildId", "sourceCommit", "packageIdentity", "manifestHash", "policyHash"}
_COMPONENT_KEYS = {
    "manifest",
    "nativePackage",
    "managedPolicy",
    "ownershipAndAcl",
    "supervisor",
    "deviceKey",
    "harnessCoverage",
    "installationIdentity",
    "leaseContinuity",
    "daemon",
    "commandShadowing",
    "update",
}
_HARNESS_KEYS = {"required", "protected", "degraded", "missing"}
_CONTINUITY_KEYS = {"monotonicUptimeSeconds", "sequence", "previousLeaseDigest", "bootSessionId"}
_BASIC_COMPONENT_KEYS = {"state", "healthy", "reasonCode"}
_INTEGRITY_STATES = frozenset(get_args(IntegrityState))
_SUPERVISOR_STATES = frozenset(get_args(SupervisorState))
_KEY_LEVELS = frozenset(get_args(KeyProtectionLevel))
_REASON_CODES = frozenset(get_args(IntegrityReasonCode))


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
    lease: SignedHealthLease
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


def _validate_snapshot_binding(snapshot: bytes, claims: HealthLeaseClaims) -> None:
    raw = _strict_json(snapshot, maximum=MAX_SNAPSHOT_BYTES, reason="health_lease_outbox_invalid")
    _exact_keys(raw, _SNAPSHOT_KEYS, "health_lease_outbox_invalid")
    if raw.get("schemaVersion") != claims.snapshot_schema_version:
        raise ValueError("health_lease_outbox_invalid")
    identifiers = raw.get("identifiers")
    product = raw.get("product")
    components = raw.get("components")
    harness = raw.get("harnessCoverage")
    continuity = raw.get("continuity")
    if not all(isinstance(value, dict) for value in (identifiers, product, components, harness, continuity)):
        raise ValueError("health_lease_outbox_invalid")
    assert isinstance(identifiers, dict)
    assert isinstance(product, dict)
    assert isinstance(components, dict)
    assert isinstance(harness, dict)
    assert isinstance(continuity, dict)
    for value, keys in (
        (identifiers, _IDENTIFIER_KEYS),
        (product, _PRODUCT_KEYS),
        (components, _COMPONENT_KEYS),
        (harness, _HARNESS_KEYS),
        (continuity, _CONTINUITY_KEYS),
    ):
        _exact_keys(value, keys, "health_lease_outbox_invalid")
    for name, component in components.items():
        if not isinstance(component, dict):
            raise ValueError("health_lease_outbox_invalid")
        expected = _BASIC_COMPONENT_KEYS | ({"level"} if name == "deviceKey" else set())
        _exact_keys(component, expected, "health_lease_outbox_invalid")
        allowed_states = _SUPERVISOR_STATES if name == "supervisor" else _INTEGRITY_STATES
        state = component.get("state")
        reason_code = component.get("reasonCode")
        level = component.get("level")
        if (
            not isinstance(state, str)
            or state not in allowed_states
            or not isinstance(component.get("healthy"), bool)
            or not isinstance(reason_code, str)
            or reason_code not in _REASON_CODES
            or (name == "deviceKey" and (not isinstance(level, str) or level not in _KEY_LEVELS))
        ):
            raise ValueError("health_lease_outbox_invalid")
    generated_at = raw.get("generatedAt")
    if not isinstance(generated_at, str):
        raise ValueError("health_lease_outbox_invalid")
    try:
        generated = datetime.fromisoformat(generated_at)
    except ValueError as exc:
        raise ValueError("health_lease_outbox_invalid") from exc
    reason_codes = raw.get("reasonCodes")
    if (
        generated.tzinfo is None
        or len(generated_at.encode("utf-8")) > 64
        or raw.get("scope") != "machine"
        or not isinstance(raw.get("healthy"), bool)
        or raw.get("assuranceLevel") not in get_args(AssuranceLevel)
        or raw.get("installOwner") not in get_args(InstallOwner)
        or raw.get("remediationClass") not in get_args(RemediationClass)
        or not isinstance(reason_codes, list)
        or len(reason_codes) > 128
        or any(not isinstance(reason, str) or reason not in _REASON_CODES for reason in reason_codes)
        or reason_codes != sorted(set(reason_codes))
    ):
        raise ValueError("health_lease_outbox_invalid")
    _bounded_string(raw.get("platform"), maximum=64)
    _bounded_string(raw.get("architecture"), maximum=64)
    _bounded_string(product.get("version"), maximum=128)
    _bounded_string(product.get("buildId"), maximum=256, nullable=True)
    _bounded_string(product.get("sourceCommit"), maximum=256, nullable=True)
    _bounded_string(product.get("packageIdentity"), maximum=256)
    for name in ("manifestHash", "policyHash"):
        value = product.get(name)
        if value is not None:
            _match(value, _HEX_64)
    for value in harness.values():
        _optional_uint64(value)
    uptime = continuity.get("monotonicUptimeSeconds")
    if uptime is not None and (
        not isinstance(uptime, (int, float)) or isinstance(uptime, bool) or not math.isfinite(uptime) or uptime < 0
    ):
        raise ValueError("health_lease_outbox_invalid")
    _optional_uint64(continuity.get("sequence"))
    previous = continuity.get("previousLeaseDigest")
    if previous is not None:
        _match(previous, _HEX_64)
    _bounded_string(continuity.get("bootSessionId"), maximum=256, nullable=True)
    expected_identifiers = {
        "workspaceId": claims.workspace_id,
        "deviceId": claims.device_id,
        "machineInstallationId": claims.machine_installation_id,
        "installationGeneration": claims.installation_generation,
    }
    if any(identifiers.get(key) != value for key, value in expected_identifiers.items()):
        raise ValueError("health_lease_outbox_invalid")
    if (
        continuity.get("sequence") != claims.sequence - 1
        or continuity.get("previousLeaseDigest") != claims.previous_lease_digest
    ):
        raise ValueError("health_lease_outbox_invalid")


__all__ = [
    "HEALTH_LEASE_SIGNING_DOMAIN",
    "HealthLeaseBinding",
    "HealthLeaseClaims",
    "HealthLeaseOutbox",
    "SignedHealthLease",
    "canonical_json_bytes",
    "canonical_timestamp",
]
