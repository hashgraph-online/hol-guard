"""Strict, versioned contract for machine health leases.

The native runtime owns parsing: canonical bytes, exact keys, timestamps,
signature encodings and the snapshot an outbox carries. This module frames
the request, maps the answer onto the contract's errors and keeps the
dataclasses that sign and serialize a lease.
"""

from __future__ import annotations

import base64
import hashlib
import importlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Final, Protocol, cast

from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature

from .runtime_request import runtime_answer


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
    def from_contract(cls, claims: dict[str, Any], signature: bytes) -> ProtectionLease: ...


HEALTH_LEASE_SCHEMA: Final = "hol-guard-health-lease.v1"
HEALTH_LEASE_OUTBOX_SCHEMA: Final = "hol-guard-health-lease-outbox.v1"
HEALTH_LEASE_SIGNING_DOMAIN: Final = b"HOL-GUARD-HEALTH-LEASE-V1\x00"
HEALTH_LEASE_CONTRACT_FEATURE: Final = "native-health-lease-contract-v1"
SIGNATURE_ALGORITHM: Final = "ecdsa-p256-sha256"
SIGNATURE_ENCODING: Final = "asn1-der"
MAX_LEASE_BYTES: Final = 32 * 1024
MAX_SNAPSHOT_BYTES: Final = 256 * 1024
MAX_OUTBOX_BYTES: Final = 4 * ((MAX_SNAPSHOT_BYTES + 2) // 3) + MAX_LEASE_BYTES + 4096
P256_ORDER: Final = int("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)

_SAFE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_CONTRACT_COMMAND = "health-lease-contract"
_CONTRACT_SCHEMA = "health-lease-contract.v1"
_CONTRACT_ERRORS = {"health_lease_invalid", "health_lease_challenge_invalid", "health_lease_outbox_invalid"}
_NATIVE_UNAVAILABLE = "health_lease_contract_native_unavailable"
_COMMAND_TIMEOUT_SECONDS = 30.0
_OUTPUT_LIMIT_BYTES = 2 * MAX_OUTBOX_BYTES


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


def _native_answer(request: dict[str, object]) -> dict[str, Any] | None:
    """The runtime's answer to one contract request, or ``None`` when it cannot answer."""

    return runtime_answer(
        HEALTH_LEASE_CONTRACT_FEATURE,
        _CONTRACT_COMMAND,
        {"schema": _CONTRACT_SCHEMA, **request},
        timeout_seconds=_COMMAND_TIMEOUT_SECONDS,
        output_limit=_OUTPUT_LIMIT_BYTES,
    )


def native_contract(op: str, request: dict[str, object]) -> dict[str, Any]:
    """The native verdict on one value or payload; a refusal raises the contract's error."""

    answer = _native_answer({"op": op, **request})
    if answer is None or not isinstance(answer.get("ok"), bool):
        # A lease nothing could check is never trusted.
        raise ValueError(_NATIVE_UNAVAILABLE)
    if answer["ok"] is not True:
        reason = answer.get("reason_code")
        raise ValueError(reason if reason in _CONTRACT_ERRORS else _NATIVE_UNAVAILABLE)
    return answer


def check_value(op: str, raw: object, reason: str = "health_lease_invalid") -> dict[str, Any]:
    """``raw`` once the runtime accepts it as the value ``op`` names."""

    if not isinstance(raw, dict):
        raise ValueError(reason)
    try:
        json.dumps(raw, allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise ValueError(reason) from exc
    native_contract(op, {"value": raw})
    return cast(dict[str, Any], raw)


def parse_payload(
    op: str, payload: bytes, *, maximum: int, reason: str
) -> tuple[dict[str, Any], bytes, dict[str, Any]]:
    """The claims and DER signature of the lease ``payload`` carries, and the whole answer."""

    if not payload or len(payload) > maximum:
        raise ValueError(reason)
    answer = native_contract(op, {"payload": base64.b64encode(payload).decode("ascii")})
    claims = answer.get("claims")
    signature = answer.get("signature")
    if not isinstance(claims, dict) or not isinstance(signature, str):
        raise ValueError(_NATIVE_UNAVAILABLE)
    return cast(dict[str, Any], claims), base64.b64decode(signature, validate=True), answer


def _safe_id(value: object) -> str:
    if not isinstance(value, str) or _SAFE_ID.fullmatch(value) is None:
        raise ValueError("health_lease_invalid")
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
        return cls.from_contract(check_value("health-claims", raw))

    @classmethod
    def from_contract(cls, raw: dict[str, Any]) -> HealthLeaseClaims:
        """Claims the runtime already accepted."""

        return cls(
            raw["workspaceId"],
            raw["deviceId"],
            raw["machineInstallationId"],
            raw["installationGeneration"],
            raw["sequence"],
            raw["issuedAt"],
            raw["leaseExpiresAt"],
            raw["snapshotSchemaVersion"],
            raw["snapshotDigest"],
            raw["previousLeaseDigest"],
            raw["previousLeaseKeyId"],
            raw["signingKeyId"],
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
        claims, signature, _ = parse_payload(
            "health-lease", payload, maximum=MAX_LEASE_BYTES, reason="health_lease_invalid"
        )
        return cls(HealthLeaseClaims.from_contract(claims), signature)


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
        payload = canonical_json_bytes(self.to_dict())
        # The runtime checks the outbox as a reader would, snapshot binding included.
        parse_payload("outbox", payload, maximum=MAX_OUTBOX_BYTES, reason="health_lease_outbox_invalid")
        return payload

    @classmethod
    def parse(cls, payload: bytes) -> HealthLeaseOutbox:
        claims, signature, answer = parse_payload(
            "outbox", payload, maximum=MAX_OUTBOX_BYTES, reason="health_lease_outbox_invalid"
        )
        snapshot = answer.get("snapshot")
        if not isinstance(snapshot, str):
            raise ValueError(_NATIVE_UNAVAILABLE)
        if answer.get("kind") == "protection":
            module = importlib.import_module(".protection_lease_contract", __package__)
            lease_type = cast(type[ProtectionLease], module.SignedProtectionLease)
            lease: SignedHealthLease | ProtectionLease = lease_type.from_contract(claims, signature)
        else:
            lease = SignedHealthLease(HealthLeaseClaims.from_contract(claims), signature)
        return cls(lease, base64.b64decode(snapshot, validate=True))


__all__ = [
    "HEALTH_LEASE_SIGNING_DOMAIN",
    "HealthLeaseBinding",
    "HealthLeaseClaims",
    "HealthLeaseOutbox",
    "SignedHealthLease",
    "canonical_json_bytes",
    "canonical_timestamp",
]
