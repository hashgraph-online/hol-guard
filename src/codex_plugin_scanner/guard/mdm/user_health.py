"""Opt-in lower-assurance health leases for user-managed Guard installations."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import secrets
import stat
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import cast

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature

from ..review_contracts import guard_review_oauth_metadata
from ..store import GuardStore
from .health_lease_contract import HealthLeaseOutbox, canonical_json_bytes, canonical_timestamp
from .health_transport import GuardCloudMachineHealthTransport, MachineHealthTransport
from .integrity import machine_integrity_snapshot
from .protection_lease_contract import ProtectionLeaseClaims, SignedProtectionLease

_SCHEMA = "hol-guard-user-health-state.v1"
_STATE_NAME = "user-health-state.json"
_LOCK_NAME = "user-health-state.lock"
_MAX_STATE_BYTES = 512 * 1024
_MAX_UINT64 = (1 << 64) - 1
_P256_ORDER = int("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)


@dataclass(frozen=True, slots=True)
class UserHealthState:
    enabled: bool
    workspace_id: str
    device_id: str
    machine_installation_id: str
    installation_generation: str
    sequence: int
    last_lease_digest: str | None
    key_id: str
    public_key_spki: str
    private_key_pem: str
    pending_outbox: str | None
    updated_at: str

    def to_dict(self) -> dict[str, object]:
        return {
            "schemaVersion": _SCHEMA,
            "enabled": self.enabled,
            "workspaceId": self.workspace_id,
            "deviceId": self.device_id,
            "machineInstallationId": self.machine_installation_id,
            "installationGeneration": self.installation_generation,
            "sequence": self.sequence,
            "lastLeaseDigest": self.last_lease_digest,
            "keyId": self.key_id,
            "publicKeySpki": self.public_key_spki,
            "privateKeyPem": self.private_key_pem,
            "pendingOutbox": self.pending_outbox,
            "updatedAt": self.updated_at,
        }


def _state_path(guard_home: Path) -> Path:
    return guard_home / _STATE_NAME


def _low_s_signature(signature: bytes) -> bytes:
    try:
        r, s = decode_dss_signature(signature)
    except ValueError as exc:
        raise OSError("user_health_signature_invalid") from exc
    if not 1 <= r < _P256_ORDER or not 1 <= s < _P256_ORDER:
        raise OSError("user_health_signature_invalid")
    return encode_dss_signature(r, min(s, _P256_ORDER - s))


def _private_directory(guard_home: Path) -> None:
    metadata = guard_home.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise PermissionError("user_health_state_acl_invalid")
    if os.name != "nt" and (metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) & 0o077):
        raise PermissionError("user_health_state_acl_invalid")


def _read_state(guard_home: Path) -> UserHealthState | None:
    try:
        _private_directory(guard_home)
    except FileNotFoundError:
        return None
    try:
        descriptor = os.open(
            _state_path(guard_home),
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
    except FileNotFoundError:
        return None
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_size > _MAX_STATE_BYTES
            or (os.name != "nt" and (metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) & 0o077))
        ):
            raise PermissionError("user_health_state_acl_invalid")
        payload = os.read(descriptor, _MAX_STATE_BYTES + 1)
    finally:
        os.close(descriptor)
    try:
        raw = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("user_health_state_invalid") from exc
    expected = {
        "schemaVersion",
        "enabled",
        "workspaceId",
        "deviceId",
        "machineInstallationId",
        "installationGeneration",
        "sequence",
        "lastLeaseDigest",
        "keyId",
        "publicKeySpki",
        "privateKeyPem",
        "pendingOutbox",
        "updatedAt",
    }
    if not isinstance(raw, dict) or set(raw) != expected or raw.get("schemaVersion") != _SCHEMA:
        raise ValueError("user_health_state_invalid")
    state = UserHealthState(
        cast(bool, raw["enabled"]),
        cast(str, raw["workspaceId"]),
        cast(str, raw["deviceId"]),
        cast(str, raw["machineInstallationId"]),
        cast(str, raw["installationGeneration"]),
        cast(int, raw["sequence"]),
        cast(str | None, raw["lastLeaseDigest"]),
        cast(str, raw["keyId"]),
        cast(str, raw["publicKeySpki"]),
        cast(str, raw["privateKeyPem"]),
        cast(str | None, raw["pendingOutbox"]),
        cast(str, raw["updatedAt"]),
    )
    _validate_state(state)
    return state


def _validate_state(state: UserHealthState) -> None:
    if (
        not isinstance(state.enabled, bool)
        or not all(isinstance(value, str) and value for value in (state.workspace_id, state.device_id))
        or any(
            len(value) != 32 or any(char not in "0123456789abcdef" for char in value)
            for value in (state.machine_installation_id, state.installation_generation)
        )
        or not isinstance(state.sequence, int)
        or isinstance(state.sequence, bool)
        or not 0 <= state.sequence <= _MAX_UINT64
        or (state.sequence == 0) != (state.last_lease_digest is None)
        or (
            state.last_lease_digest is not None
            and (
                len(state.last_lease_digest) != 64
                or any(char not in "0123456789abcdef" for char in state.last_lease_digest)
            )
        )
        or len(state.key_id) != 43
        or len(state.public_key_spki) > 1024
        or len(state.private_key_pem) > 4096
        or (state.pending_outbox is not None and len(state.pending_outbox) > 400_000)
    ):
        raise ValueError("user_health_state_invalid")
    try:
        updated_at = datetime.fromisoformat(state.updated_at)
    except (TypeError, ValueError) as exc:
        raise ValueError("user_health_state_invalid") from exc
    if updated_at.tzinfo is None:
        raise ValueError("user_health_state_invalid")
    try:
        private_key = serialization.load_pem_private_key(state.private_key_pem.encode(), password=None)
        public_der = base64.b64decode(state.public_key_spki, validate=True)
        key_digest = base64.b64decode(f"{state.key_id}=", altchars=b"-_", validate=True)
    except (binascii.Error, TypeError, UnsupportedAlgorithm, ValueError) as exc:
        raise ValueError("user_health_state_invalid") from exc
    if not isinstance(private_key, ec.EllipticCurvePrivateKey) or not isinstance(private_key.curve, ec.SECP256R1):
        raise ValueError("user_health_state_invalid")
    expected_der = private_key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    if expected_der != public_der or hashlib.sha256(public_der).digest() != key_digest:
        raise ValueError("user_health_state_invalid")


@contextmanager
def _state_lock(guard_home: Path) -> Iterator[None]:
    """Serialize state mutation across foreground and background processes."""

    _private_directory(guard_home)
    descriptor = os.open(
        guard_home / _LOCK_NAME,
        os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or (
            os.name != "nt" and (metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) & 0o077)
        ):
            raise PermissionError("user_health_state_acl_invalid")
        if os.name == "nt":
            import msvcrt

            if metadata.st_size == 0:
                os.write(descriptor, b"0")
            os.lseek(descriptor, 0, os.SEEK_SET)
            msvcrt.locking(descriptor, msvcrt.LK_LOCK, 1)
        else:
            import fcntl

            fcntl.flock(descriptor, fcntl.LOCK_EX)
        try:
            yield
        finally:
            if os.name == "nt":
                import msvcrt

                os.lseek(descriptor, 0, os.SEEK_SET)
                msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(descriptor, fcntl.LOCK_UN)
    finally:
        os.close(descriptor)


def _write_state(guard_home: Path, state: UserHealthState) -> None:
    _validate_state(state)
    _private_directory(guard_home)
    payload = canonical_json_bytes(state.to_dict())
    temporary = guard_home / f".{_STATE_NAME}.{secrets.token_hex(16)}.tmp"
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, _state_path(guard_home))
        os.chmod(_state_path(guard_home), 0o600)
    finally:
        with suppress(FileNotFoundError):
            temporary.unlink()


def _new_state(workspace_id: str, device_id: str, now: datetime) -> UserHealthState:
    private_key = ec.generate_private_key(ec.SECP256R1())
    private_pem = private_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    ).decode("ascii")
    public_der = private_key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return UserHealthState(
        True,
        workspace_id,
        device_id,
        secrets.token_hex(16),
        secrets.token_hex(16),
        0,
        None,
        base64.urlsafe_b64encode(hashlib.sha256(public_der).digest()).rstrip(b"=").decode("ascii"),
        base64.b64encode(public_der).decode("ascii"),
        private_pem,
        None,
        now.isoformat(),
    )


def configure_user_health_leases(guard_home: Path, *, enabled: bool, now: datetime | None = None) -> dict[str, object]:
    """Explicitly opt a connected user installation in or out without deleting continuity."""

    resolved_now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    store = GuardStore(guard_home, prime_policy_integrity=False, source="user-health")
    identity = guard_review_oauth_metadata(store)
    with _state_lock(guard_home):
        state = _read_state(guard_home)
        if state is None or (state.workspace_id, state.device_id) != (identity.workspace_id, identity.device_id):
            state = _new_state(identity.workspace_id, identity.device_id, resolved_now)
        state = replace(state, enabled=enabled, updated_at=resolved_now.isoformat())
        _write_state(guard_home, state)
    return user_health_status(guard_home)


def user_health_status(guard_home: Path) -> dict[str, object]:
    state = _read_state(guard_home)
    return {
        "schemaVersion": "hol-guard-user-health-status.v1",
        "configured": state is not None,
        "enabled": state.enabled if state is not None else False,
        "assuranceLevel": "user-managed",
        "sequence": state.sequence if state is not None else 0,
        "pending": state.pending_outbox is not None if state is not None else False,
    }


def user_health_report_due(
    guard_home: Path,
    *,
    now: datetime | None = None,
    cadence_seconds: int = 300,
) -> bool:
    """Return whether the opted-in cadence should issue or retry a lease."""

    if not 60 <= cadence_seconds <= 3_600:
        raise ValueError("user_health_cadence_invalid")
    state = _read_state(guard_home)
    if state is None or not state.enabled:
        return False
    if state.pending_outbox is not None:
        return True
    resolved_now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    try:
        updated_at = datetime.fromisoformat(state.updated_at).astimezone(timezone.utc)
    except ValueError as exc:
        raise ValueError("user_health_state_invalid") from exc
    return (resolved_now - updated_at).total_seconds() >= cadence_seconds


def _registration(state: UserHealthState, now: datetime) -> bytes:
    registration: dict[str, object] = {
        "algorithm": "ecdsa-p256-sha256",
        "deviceId": state.device_id,
        "installationGeneration": state.installation_generation,
        "keyId": state.key_id,
        "machineInstallationId": state.machine_installation_id,
        "previousInstallationGeneration": None,
        "publicKeySpki": state.public_key_spki,
        "registeredAt": canonical_timestamp(now),
        "schemaVersion": "hol-guard-health-key-registration.v1",
        "workspaceId": state.workspace_id,
    }
    private_key = serialization.load_pem_private_key(state.private_key_pem.encode(), password=None)
    assert isinstance(private_key, ec.EllipticCurvePrivateKey)
    signature = _low_s_signature(private_key.sign(canonical_json_bytes(registration), ec.ECDSA(hashes.SHA256())))
    return canonical_json_bytes(
        {
            **registration,
            "proof": {
                "algorithm": "ecdsa-p256-sha256",
                "encoding": "asn1-der",
                "value": base64.b64encode(signature).decode("ascii"),
            },
        }
    )


def _outbox(state: UserHealthState, now: datetime) -> HealthLeaseOutbox:
    if state.pending_outbox is not None:
        pending = HealthLeaseOutbox.parse(base64.b64decode(state.pending_outbox, validate=True))
        expires_at = datetime.fromisoformat(pending.lease.claims.lease_expires_at.replace("Z", "+00:00"))
        if now < expires_at:
            return pending
    snapshot = dict(machine_integrity_snapshot())
    snapshot["assuranceLevel"] = "user-managed"
    snapshot["installOwner"] = "user"
    snapshot["identifiers"] = {
        "workspaceId": state.workspace_id,
        "deviceId": state.device_id,
        "machineInstallationId": state.machine_installation_id,
        "installationGeneration": state.installation_generation,
    }
    continuity = cast(dict[str, object], snapshot["continuity"])
    snapshot["continuity"] = {**continuity, "sequence": state.sequence, "previousLeaseDigest": state.last_lease_digest}
    snapshot_bytes = canonical_json_bytes(snapshot)
    claims = ProtectionLeaseClaims.parse(
        {
            "workspaceId": state.workspace_id,
            "deviceId": state.device_id,
            "machineInstallationId": state.machine_installation_id,
            "installationGeneration": state.installation_generation,
            "sequence": state.sequence + 1,
            "issuedAt": canonical_timestamp(now),
            "validForSeconds": 900,
            "snapshotSchemaVersion": "local-integrity-snapshot.v1",
            "snapshotDigest": hashlib.sha256(snapshot_bytes).hexdigest(),
            "previousLeaseDigest": state.last_lease_digest,
            "signingKeyId": state.key_id,
            "challenge": None,
        }
    )
    private_key = serialization.load_pem_private_key(state.private_key_pem.encode(), password=None)
    assert isinstance(private_key, ec.EllipticCurvePrivateKey)
    signature = _low_s_signature(private_key.sign(claims.signing_payload(), ec.ECDSA(hashes.SHA256())))
    return HealthLeaseOutbox(
        SignedProtectionLease.parse(SignedProtectionLease(claims, signature).canonical_bytes()), snapshot_bytes
    )


def run_user_health_cadence(
    guard_home: Path, *, now: datetime | None = None, transport: MachineHealthTransport | None = None
) -> dict[str, object]:
    """Register and deliver the exact durable pending user-managed lease."""

    resolved_now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc).replace(microsecond=0)
    with _state_lock(guard_home):
        state = _read_state(guard_home)
        if state is None or not state.enabled:
            raise PermissionError("user_health_opt_in_required")
        outbox = _outbox(state, resolved_now)
        encoded_outbox = base64.b64encode(outbox.canonical_bytes()).decode("ascii")
        if state.pending_outbox != encoded_outbox:
            state = replace(
                state,
                pending_outbox=encoded_outbox,
                updated_at=resolved_now.isoformat(),
            )
            _write_state(guard_home, state)
    resolved_transport = transport or GuardCloudMachineHealthTransport(guard_home)
    if state.sequence == 0:
        resolved_transport.register_key(_registration(state, resolved_now))
    ack = resolved_transport.deliver_lease(outbox)
    claims = outbox.lease.claims
    expected = (
        state.workspace_id,
        state.device_id,
        state.machine_installation_id,
        state.installation_generation,
        claims.sequence,
        outbox.lease.digest,
    )
    actual = (
        ack.workspace_id,
        ack.device_id,
        ack.machine_installation_id,
        ack.installation_generation,
        ack.sequence,
        ack.lease_digest,
    )
    if actual != expected:
        raise OSError("health_lease_ack_conflict")
    with _state_lock(guard_home):
        current = _read_state(guard_home)
        if current is None:
            raise OSError("health_lease_state_conflict")
        already_committed = (
            current.pending_outbox is None
            and current.sequence == claims.sequence
            and current.last_lease_digest == outbox.lease.digest
        )
        if not already_committed:
            if (
                current.pending_outbox != encoded_outbox
                or current.sequence != state.sequence
                or current.last_lease_digest != state.last_lease_digest
            ):
                raise OSError("health_lease_state_conflict")
            _write_state(
                guard_home,
                replace(
                    current,
                    sequence=claims.sequence,
                    last_lease_digest=outbox.lease.digest,
                    pending_outbox=None,
                    updated_at=ack.received_datetime.isoformat(),
                ),
            )
    return {
        "schemaVersion": "hol-guard-user-health-report.v1",
        "delivered": True,
        "assuranceLevel": "user-managed",
        "workspaceId": state.workspace_id,
        "deviceId": state.device_id,
        "sequence": claims.sequence,
        "leaseDigest": outbox.lease.digest,
        "receivedAt": ack.received_at,
    }


__all__ = [
    "configure_user_health_leases",
    "run_user_health_cadence",
    "user_health_report_due",
    "user_health_status",
]
