"""Crash-consistent local health-lease issuance with a single protected outbox."""

from __future__ import annotations

import base64
import hashlib
import json
import platform
import time
from collections.abc import Callable, Mapping
from dataclasses import replace
from datetime import datetime, timezone
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
from .health_lease_ack import HealthLeaseAck
from .health_lease_contract import (
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
    MAX_PROTECTION_LEASE_SECONDS,
    MIN_PROTECTION_LEASE_SECONDS,
    ProtectionLeaseChallenge,
    ProtectionLeaseClaims,
    SignedProtectionLease,
)

HEALTH_LEASE_STATE_FEATURE = "native-health-lease-state-v1"
HEALTH_LEASE_STATE_COMMAND = "health-lease-state"
HEALTH_LEASE_STATE_SCHEMA = "health-lease-state.v1"
_STATUS_TIMEOUT_SECONDS = 10.0
_COMMAND_TIMEOUT_SECONDS = 30.0
_OUTPUT_LIMIT_BYTES = 1024 * 1024
_STATE_UNAVAILABLE = "health_lease_state_native_unavailable"
_STATE_ERROR_TYPES: dict[str, type[OSError]] = {
    "permission": PermissionError,
    "exists": FileExistsError,
    "os": OSError,
}
SnapshotFactory = Callable[[], LocalIntegritySnapshot]
LeaseClaims = HealthLeaseClaims | ProtectionLeaseClaims
LeaseSigner = Callable[[MachinePaths, KeyGeneration, LeaseClaims, str], bytes]
CrashHook = Callable[[str], None]


def _state_owner_uid() -> int:
    """The only owner a Unix state file is trusted from; Windows skips the check."""

    return 0


def _native_state(op: str, kind: str, paths: MachinePaths, content: bytes | None = None) -> dict[str, object]:
    """Ask the native runtime to read or write one lease state file.

    The runtime opens without following links, trusts only a private regular
    file of the state owner that held still while read, and writes through a
    synced private temporary file. Without it the lease fails closed.
    """

    from ..native_runtime import _run_native_process, native_runtime_status

    status = native_runtime_status(deadline_monotonic=time.monotonic() + _STATUS_TIMEOUT_SECONDS)
    if (
        not status.available
        or not status.compatible
        or status.identity is None
        or status.capabilities is None
        or HEALTH_LEASE_STATE_FEATURE not in status.capabilities.features
    ):
        raise OSError(_STATE_UNAVAILABLE)
    request: dict[str, object] = {
        "schema": HEALTH_LEASE_STATE_SCHEMA,
        "op": op,
        "kind": kind,
        "state_root": str(paths.state_root),
        "owner_uid": _state_owner_uid(),
    }
    if content is not None:
        request["content"] = base64.b64encode(content).decode("ascii")
    output = _run_native_process(
        status.identity.path,
        (HEALTH_LEASE_STATE_COMMAND, "--stdin"),
        input_text=json.dumps(request, sort_keys=True),
        timeout_seconds=_COMMAND_TIMEOUT_SECONDS,
        output_limit=_OUTPUT_LIMIT_BYTES,
    )
    try:
        response = cast(object, json.loads(output)) if output is not None else None
    except ValueError:
        response = None
    if not isinstance(response, dict):
        raise OSError(_STATE_UNAVAILABLE)
    answer = cast(dict[str, object], response)
    if answer.get("ok") is True:
        return answer
    reason_code = answer.get("reason_code")
    error_type = _STATE_ERROR_TYPES.get(str(answer.get("error_class")))
    if error_type is None or not isinstance(reason_code, str):
        raise OSError(_STATE_UNAVAILABLE)
    raise error_type(reason_code)


def _atomic_outbox_write(paths: MachinePaths, outbox: HealthLeaseOutbox) -> None:
    _ = _native_state("create", "outbox", paths, outbox.canonical_bytes())


def _atomic_ack_write(paths: MachinePaths, ack: HealthLeaseAck) -> None:
    _ = _native_state("replace", "ack", paths, ack.canonical_bytes())


def _read_state(paths: MachinePaths, kind: str) -> bytes | None:
    content = _native_state("read", kind, paths).get("content")
    if content is None:
        return None
    if not isinstance(content, str):
        raise OSError(_STATE_UNAVAILABLE)
    return base64.b64decode(content, validate=True)


def _load_pending(paths: MachinePaths) -> HealthLeaseOutbox | None:
    payload = _read_state(paths, "outbox")
    return None if payload is None else HealthLeaseOutbox.parse(payload)


def _load_ack(paths: MachinePaths) -> HealthLeaseAck | None:
    payload = _read_state(paths, "ack")
    return None if payload is None else HealthLeaseAck.parse(payload)


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
    _ = _native_state("remove", "outbox", paths)


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
    if not MIN_PROTECTION_LEASE_SECONDS <= lease_seconds <= MAX_PROTECTION_LEASE_SECONDS:
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
]
