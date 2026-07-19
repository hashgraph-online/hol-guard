"""Crash-consistent local health-lease issuance with a single protected outbox."""

from __future__ import annotations

import base64
import errno
import hashlib
import os
import platform
import secrets
import stat
from collections.abc import Callable, Mapping
from contextlib import suppress
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from typing import cast

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from .continuity import (
    InstallationContinuityRecord,
    _atomic_write,
    _continuity_lock,
    _read_record,
    observe_boot,
)
from .contracts import LOCAL_INTEGRITY_SNAPSHOT_SCHEMA_VERSION, LocalIntegritySnapshot, MachinePaths
from .device_key import KeyGeneration
from .device_key_access import verified_machine_device_key_by_id
from .health_lease_ack import MAX_ACK_BYTES, HealthLeaseAck
from .health_lease_contract import (
    MAX_LEASE_SECONDS,
    MAX_OUTBOX_BYTES,
    MAX_SNAPSHOT_BYTES,
    HealthLeaseBinding,
    HealthLeaseClaims,
    HealthLeaseOutbox,
    SignedHealthLease,
    canonical_json_bytes,
    canonical_timestamp,
)
from .integrity import machine_integrity_snapshot
from .protection_lease_contract import (
    ProtectionLeaseChallenge,
    ProtectionLeaseClaims,
    SignedProtectionLease,
)

_OUTBOX_NAME = "health-lease-outbox.json"
_ACK_NAME = "health-lease-ack.json"
SnapshotFactory = Callable[[], LocalIntegritySnapshot]
LeaseClaims = HealthLeaseClaims | ProtectionLeaseClaims
LeaseSigner = Callable[[MachinePaths, KeyGeneration, LeaseClaims, str], bytes]
CrashHook = Callable[[str], None]


def _outbox_path(paths: MachinePaths) -> Path:
    return paths.state_root / _OUTBOX_NAME


def _ack_path(paths: MachinePaths) -> Path:
    return paths.state_root / _ACK_NAME


def _private_regular_file(metadata: os.stat_result) -> bool:
    return stat.S_ISREG(metadata.st_mode) and (
        os.name == "nt" or (metadata.st_uid == 0 and not stat.S_IMODE(metadata.st_mode) & 0o077)
    )


def _read_bounded(path: Path, *, maximum: int, acl_reason: str, invalid_reason: str) -> bytes:
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0))
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise PermissionError(acl_reason) from exc
        raise
    try:
        before = os.fstat(descriptor)
        if before.st_size > maximum or not _private_regular_file(before):
            raise PermissionError(acl_reason)
        payload = os.read(descriptor, maximum + 1)
        after = os.fstat(descriptor)
        before_identity = (before.st_dev, before.st_ino, before.st_size, before.st_ctime_ns)
        after_identity = (after.st_dev, after.st_ino, after.st_size, after.st_ctime_ns)
        if len(payload) != before.st_size or before_identity != after_identity:
            raise OSError(invalid_reason)
        return payload
    finally:
        os.close(descriptor)


def _fsync_directory(path: Path) -> None:
    if os.name == "nt":
        return
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    except OSError as exc:
        if exc.errno in {errno.EINVAL, errno.ENOTSUP}:
            return
        raise
    try:
        try:
            os.fsync(descriptor)
        except OSError as exc:
            if exc.errno not in {errno.EINVAL, errno.ENOTSUP}:
                raise
    finally:
        os.close(descriptor)


def _atomic_create(paths: MachinePaths, target: Path, payload: bytes, *, conflict_reason: str) -> None:
    parent = paths.state_root
    if parent.is_symlink() or not parent.is_dir():
        raise OSError("health_lease_state_root_invalid")
    if target.exists() or target.is_symlink():
        raise FileExistsError(conflict_reason)
    temporary = parent / f".{target.name}.{secrets.token_hex(16)}.tmp"
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        if os.name == "nt":
            os.link(temporary, target)
        else:
            os.link(temporary, target, follow_symlinks=False)
        _fsync_directory(parent)
    finally:
        with suppress(FileNotFoundError):
            temporary.unlink()


def _atomic_outbox_write(paths: MachinePaths, outbox: HealthLeaseOutbox) -> None:
    _atomic_create(
        paths,
        _outbox_path(paths),
        outbox.canonical_bytes(),
        conflict_reason="health_lease_pending_conflict",
    )


def _atomic_ack_write(paths: MachinePaths, ack: HealthLeaseAck) -> None:
    parent = paths.state_root
    if parent.is_symlink() or not parent.is_dir():
        raise OSError("health_lease_state_root_invalid")
    target = _ack_path(paths)
    temporary = parent / f".{target.name}.{secrets.token_hex(16)}.tmp"
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            handle.write(ack.canonical_bytes())
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, target)
        _fsync_directory(parent)
    finally:
        with suppress(FileNotFoundError):
            temporary.unlink()


def _load_pending(paths: MachinePaths) -> HealthLeaseOutbox | None:
    try:
        return HealthLeaseOutbox.parse(
            _read_bounded(
                _outbox_path(paths),
                maximum=MAX_OUTBOX_BYTES,
                acl_reason="health_lease_outbox_acl_invalid",
                invalid_reason="health_lease_outbox_invalid",
            )
        )
    except FileNotFoundError:
        return None


def _load_ack(paths: MachinePaths) -> HealthLeaseAck | None:
    try:
        return HealthLeaseAck.parse(
            _read_bounded(
                _ack_path(paths),
                maximum=MAX_ACK_BYTES,
                acl_reason="health_lease_ack_acl_invalid",
                invalid_reason="health_lease_ack_invalid",
            )
        )
    except FileNotFoundError:
        return None


def load_pending_health_lease(paths: MachinePaths) -> HealthLeaseOutbox | None:
    """Read an exact pending artifact without changing continuity state."""

    return _load_pending(paths)


def _normalized_snapshot(
    snapshot: Mapping[str, object], binding: HealthLeaseBinding, record: InstallationContinuityRecord
) -> bytes:
    if snapshot.get("schemaVersion") != LOCAL_INTEGRITY_SNAPSHOT_SCHEMA_VERSION:
        raise ValueError("health_lease_snapshot_invalid")
    identifiers = snapshot.get("identifiers")
    continuity = snapshot.get("continuity")
    if not isinstance(identifiers, dict) or not isinstance(continuity, dict):
        raise ValueError("health_lease_snapshot_invalid")
    for key, expected in (
        ("machineInstallationId", record.machine_installation_id),
        ("installationGeneration", record.installation_generation),
    ):
        if identifiers.get(key) != expected:
            raise ValueError("health_lease_snapshot_invalid")
    if identifiers.get("workspaceId") not in {None, binding.workspace_id}:
        raise ValueError("health_lease_snapshot_invalid")
    if identifiers.get("deviceId") not in {None, binding.device_id}:
        raise ValueError("health_lease_snapshot_invalid")
    if continuity.get("sequence") != record.last_issued_sequence:
        raise ValueError("health_lease_snapshot_invalid")
    if continuity.get("previousLeaseDigest") != record.last_lease_digest:
        raise ValueError("health_lease_snapshot_invalid")
    normalized = dict(snapshot)
    normalized["identifiers"] = {
        **identifiers,
        "workspaceId": binding.workspace_id,
        "deviceId": binding.device_id,
    }
    payload = canonical_json_bytes(normalized)
    if not payload or len(payload) > MAX_SNAPSHOT_BYTES:
        raise ValueError("health_lease_snapshot_invalid")
    return payload


def _verify_signature(generation: KeyGeneration, claims: LeaseClaims, signature: bytes) -> None:
    try:
        public_key = serialization.load_der_public_key(base64.b64decode(generation.public_key_spki, validate=True))
        if not isinstance(public_key, ec.EllipticCurvePublicKey) or not isinstance(public_key.curve, ec.SECP256R1):
            raise ValueError("health_lease_signing_key_invalid")
        public_key.verify(signature, claims.signing_payload(), ec.ECDSA(hashes.SHA256()))
    except (ValueError, InvalidSignature) as exc:
        raise OSError("health_lease_signature_invalid") from exc


def _default_signer(paths: MachinePaths, generation: KeyGeneration, claims: LeaseClaims, system_name: str) -> bytes:
    from .device_key_native import sign_health_lease, sign_protection_lease

    if isinstance(claims, ProtectionLeaseClaims):
        result = sign_protection_lease(paths, generation.generation, claims.signing_payload(), system_name=system_name)
    else:
        result = sign_health_lease(
            paths, generation.generation, canonical_json_bytes(claims.to_dict()), system_name=system_name
        )
    return result.signature


def _validate_pending(
    pending: HealthLeaseOutbox,
    binding: HealthLeaseBinding,
    record: InstallationContinuityRecord,
) -> bool:
    claims = pending.lease.claims
    if (
        claims.workspace_id != binding.workspace_id
        or claims.device_id != binding.device_id
        or claims.machine_installation_id != record.machine_installation_id
        or claims.installation_generation != record.installation_generation
    ):
        raise OSError("health_lease_pending_conflict")
    if claims.sequence == record.last_issued_sequence:
        if record.last_lease_digest != pending.lease.digest or record.last_lease_key_id != claims.signing_key_id:
            raise OSError("health_lease_pending_conflict")
        return False
    if claims.sequence != record.last_issued_sequence + 1:
        raise OSError("health_lease_pending_conflict")
    if claims.previous_lease_digest != record.last_lease_digest or (
        isinstance(claims, HealthLeaseClaims) and claims.previous_lease_key_id != record.last_lease_key_id
    ):
        raise OSError("health_lease_pending_conflict")
    return True


def _ack_matches_pending(ack: HealthLeaseAck, pending: HealthLeaseOutbox) -> bool:
    claims = pending.lease.claims
    return (
        ack.workspace_id == claims.workspace_id
        and ack.device_id == claims.device_id
        and ack.machine_installation_id == claims.machine_installation_id
        and ack.installation_generation == claims.installation_generation
        and ack.sequence == claims.sequence
        and ack.lease_digest == pending.lease.digest
    )


def _ack_matches_record(
    ack: HealthLeaseAck,
    binding: HealthLeaseBinding,
    record: InstallationContinuityRecord,
) -> bool:
    return (
        ack.workspace_id == binding.workspace_id
        and ack.device_id == binding.device_id
        and ack.machine_installation_id == record.machine_installation_id
        and ack.installation_generation == record.installation_generation
        and ack.sequence == record.last_issued_sequence
        and ack.lease_digest == record.last_lease_digest
    )


def _validate_ack(ack: HealthLeaseAck, pending: HealthLeaseOutbox) -> None:
    if not _ack_matches_pending(ack, pending):
        raise OSError("health_lease_ack_conflict")
    claims = pending.lease.claims
    issued = datetime.strptime(claims.issued_at, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    expires = datetime.strptime(claims.lease_expires_at, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    if not issued <= ack.received_datetime < expires:
        raise OSError("health_lease_ack_stale")


def _retire_outbox(paths: MachinePaths) -> None:
    try:
        _outbox_path(paths).unlink()
    except FileNotFoundError:
        return
    _fsync_directory(paths.state_root)


def _advanced_record(
    record: InstallationContinuityRecord,
    lease: SignedHealthLease | SignedProtectionLease,
    *,
    system_name: str,
    now: datetime,
) -> InstallationContinuityRecord:
    observation = observe_boot(system_name=system_name)
    return replace(
        record,
        last_issued_sequence=lease.claims.sequence,
        last_lease_digest=lease.digest,
        last_lease_boot_session_id=observation.boot_session_id,
        last_lease_monotonic_uptime_ns=observation.monotonic_uptime_ns,
        last_lease_key_id=lease.claims.signing_key_id,
        updated_at=now.astimezone(timezone.utc).isoformat(),
    )


def acknowledge_pending_health_lease(
    paths: MachinePaths,
    binding: HealthLeaseBinding,
    payload: bytes,
    *,
    system_name: str | None = None,
    crash_hook: CrashHook | None = None,
) -> HealthLeaseAck:
    """Durably retire one pending lease after an authenticated Cloud response."""

    ack = HealthLeaseAck.parse(payload)
    resolved_system = system_name or platform.system()
    with _continuity_lock(paths):
        record = _read_record(paths)
        if record is None:
            raise OSError("installation_identity_absent")
        existing_ack = _load_ack(paths)
        pending = _load_pending(paths)
        if pending is None:
            if existing_ack == ack and _ack_matches_record(ack, binding, record):
                return ack
            raise OSError("health_lease_outbox_absent")
        requires_recovery = _validate_pending(pending, binding, record)
        generation = verified_machine_device_key_by_id(
            paths,
            pending.lease.claims.signing_key_id,
            system_name=resolved_system,
        )
        _verify_signature(generation, cast(LeaseClaims, pending.lease.claims), pending.lease.signature)
        _validate_ack(ack, pending)
        if requires_recovery:
            recovered = _advanced_record(
                record,
                cast(SignedHealthLease | SignedProtectionLease, pending.lease),
                system_name=resolved_system,
                now=ack.received_datetime,
            )
            _atomic_write(paths, recovered)
        if existing_ack != ack:
            _atomic_ack_write(paths, ack)
        if crash_hook is not None:
            crash_hook("ack-durable")
        _retire_outbox(paths)
        if crash_hook is not None:
            crash_hook("outbox-retired")
        return ack


def issue_or_load_pending_health_lease(
    paths: MachinePaths,
    binding: HealthLeaseBinding,
    *,
    now: datetime | None = None,
    lease_seconds: int = 900,
    system_name: str | None = None,
    snapshot_factory: SnapshotFactory = machine_integrity_snapshot,
    signer: LeaseSigner = _default_signer,
    crash_hook: CrashHook | None = None,
    challenge: ProtectionLeaseChallenge | None = None,
) -> HealthLeaseOutbox:
    """Issue one lease or recover the exact pending artifact after a crash."""

    requested_now = now or datetime.now(timezone.utc)
    if requested_now.tzinfo is None or requested_now.utcoffset() is None:
        raise ValueError("health_lease_time_invalid")
    resolved_now = requested_now.astimezone(timezone.utc).replace(microsecond=0)
    resolved_system = system_name or platform.system()
    if not 1 <= lease_seconds <= MAX_LEASE_SECONDS:
        raise ValueError("health_lease_duration_invalid")
    with _continuity_lock(paths):
        record = _read_record(paths)
        if record is None:
            raise OSError("installation_identity_absent")
        pending = _load_pending(paths)
        ack = _load_ack(paths)
        if pending is not None:
            requires_recovery = _validate_pending(pending, binding, record)
            generation = verified_machine_device_key_by_id(
                paths,
                pending.lease.claims.signing_key_id,
                system_name=resolved_system,
            )
            _verify_signature(generation, cast(LeaseClaims, pending.lease.claims), pending.lease.signature)
            if requires_recovery:
                recovered = _advanced_record(
                    record,
                    cast(SignedHealthLease | SignedProtectionLease, pending.lease),
                    system_name=resolved_system,
                    now=resolved_now,
                )
                _atomic_write(paths, recovered)
                record = recovered
            if ack is not None and _ack_matches_pending(ack, pending):
                _validate_ack(ack, pending)
                if resolved_now < ack.received_datetime:
                    raise OSError("health_lease_clock_rollback")
                _retire_outbox(paths)
                pending = None
            else:
                expires = datetime.strptime(pending.lease.claims.lease_expires_at, "%Y-%m-%dT%H:%M:%SZ").replace(
                    tzinfo=timezone.utc
                )
                if resolved_now >= expires:
                    # An expired unacknowledged artifact remains durable evidence. It
                    # cannot be erased or replaced with a synthetic historical lease.
                    raise OSError("health_lease_pending_expired")
                return pending
        if record.last_issued_sequence == (1 << 64) - 1:
            raise OSError("lease_continuity_sequence_exhausted")
        if record.last_issued_sequence > 0 and (ack is None or not _ack_matches_record(ack, binding, record)):
            raise OSError("health_lease_outbox_absent")
        generation = verified_machine_device_key_by_id(paths, system_name=resolved_system)
        snapshot_bytes = _normalized_snapshot(snapshot_factory(), binding, record)
        claims = ProtectionLeaseClaims.parse(
            {
                "workspaceId": binding.workspace_id,
                "deviceId": binding.device_id,
                "machineInstallationId": record.machine_installation_id,
                "installationGeneration": record.installation_generation,
                "sequence": record.last_issued_sequence + 1,
                "issuedAt": canonical_timestamp(resolved_now),
                "validForSeconds": lease_seconds,
                "snapshotSchemaVersion": LOCAL_INTEGRITY_SNAPSHOT_SCHEMA_VERSION,
                "snapshotDigest": hashlib.sha256(snapshot_bytes).hexdigest(),
                "previousLeaseDigest": record.last_lease_digest,
                "signingKeyId": generation.key_id,
                "challenge": challenge.to_dict() if challenge is not None else None,
            }
        )
        signature = signer(paths, generation, claims, resolved_system)
        lease = SignedProtectionLease.parse(SignedProtectionLease(claims, signature).canonical_bytes())
        _verify_signature(generation, claims, lease.signature)
        outbox = HealthLeaseOutbox(lease, snapshot_bytes)
        _atomic_outbox_write(paths, outbox)
        if crash_hook is not None:
            crash_hook("outbox-durable")
        _atomic_write(paths, _advanced_record(record, lease, system_name=resolved_system, now=resolved_now))
        if crash_hook is not None:
            crash_hook("continuity-durable")
        return outbox


__all__ = [
    "acknowledge_pending_health_lease",
    "issue_or_load_pending_health_lease",
    "load_pending_health_lease",
]
