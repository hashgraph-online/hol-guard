"""Journaled machine device-key lifecycle backed by platform-native keystores."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import platform
import secrets
import stat
import subprocess
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import BinaryIO, Literal, cast

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from .contracts import KeyProtectionLevel, KeyProtectionStatus, MachinePaths, default_machine_paths
from .device_key_native import (
    NativeKeyEvidence,
)
from .device_key_native import (
    run_helper as _run_helper,
)
from .device_key_native import (
    windows_current_user_sid as _windows_current_user_sid,
)

_METADATA_SCHEMA = "hol-guard-device-key.v1"
_METADATA_NAME = "device-key.json"
_LOCK_NAME = ".device-key.lock"
_MAX_METADATA_BYTES = 64 * 1024
_SYSTEM_SID = "S-1-5-18"

LifecycleState = Literal["pending", "active", "rotation_pending", "revoked"]


@dataclass(frozen=True, slots=True)
class KeyGeneration:
    generation: str
    key_id: str
    public_key_spki: str
    protection_level: KeyProtectionLevel
    created_at: str

    def to_dict(self) -> dict[str, str]:
        return {
            "generation": self.generation,
            "keyId": self.key_id,
            "publicKeySpki": self.public_key_spki,
            "protectionLevel": self.protection_level,
            "createdAt": self.created_at,
        }


@dataclass(frozen=True, slots=True)
class DeviceKeyMetadata:
    state: LifecycleState
    active: KeyGeneration | None
    pending_generation: str | None
    previous: KeyGeneration | None
    updated_at: str

    def to_dict(self) -> dict[str, object]:
        return {
            "schemaVersion": _METADATA_SCHEMA,
            "state": self.state,
            "active": self.active.to_dict() if self.active is not None else None,
            "pendingGeneration": self.pending_generation,
            "previous": self.previous.to_dict() if self.previous is not None else None,
            "updatedAt": self.updated_at,
        }


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _metadata_path(paths: MachinePaths) -> Path:
    return paths.state_root / _METADATA_NAME


def _lock_path(paths: MachinePaths) -> Path:
    return paths.state_root / _LOCK_NAME


def _bounded_private_file(path: Path) -> bytes:
    descriptor = os.open(
        path,
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size > _MAX_METADATA_BYTES:
            raise OSError("device_key_metadata_invalid")
        if os.name != "nt" and (before.st_uid != 0 or stat.S_IMODE(before.st_mode) & 0o077):
            raise PermissionError("device_key_acl_invalid")
        payload = os.read(descriptor, _MAX_METADATA_BYTES + 1)
        after = os.fstat(descriptor)
        if (
            len(payload) > _MAX_METADATA_BYTES
            or len(payload) != before.st_size
            or (before.st_dev, before.st_ino, before.st_size, before.st_ctime_ns)
            != (after.st_dev, after.st_ino, after.st_size, after.st_ctime_ns)
        ):
            raise OSError("device_key_metadata_changed")
        return payload
    finally:
        os.close(descriptor)


def _atomic_metadata_write(paths: MachinePaths, metadata: DeviceKeyMetadata) -> None:
    parent = paths.state_root
    if parent.is_symlink() or not parent.is_dir():
        raise OSError("device_key_state_root_invalid")
    target = _metadata_path(paths)
    temporary = parent / f".{target.name}.{secrets.token_hex(16)}.tmp"
    payload = json.dumps(metadata.to_dict(), sort_keys=True, separators=(",", ":")).encode("utf-8")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, target)
        if os.name != "nt":
            directory_descriptor = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(directory_descriptor)
            finally:
                os.close(directory_descriptor)
    finally:
        with suppress(FileNotFoundError):
            temporary.unlink()


def _acquire_lock(handle: BinaryIO) -> None:
    if os.name == "nt":
        import msvcrt

        handle.seek(0)
        if not handle.read(1):
            handle.write(b"0")
            handle.flush()
        handle.seek(0)
        msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
        return
    import fcntl

    fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)


def _release_lock(handle: BinaryIO) -> None:
    if os.name == "nt":
        import msvcrt

        handle.seek(0)
        msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
        return
    import fcntl

    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


@contextmanager
def _machine_key_lock(paths: MachinePaths) -> Iterator[None]:
    if paths.state_root.is_symlink() or not paths.state_root.is_dir():
        raise OSError("device_key_state_root_invalid")
    descriptor = os.open(
        _lock_path(paths),
        os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    with os.fdopen(descriptor, "r+b", closefd=True) as handle:
        metadata = os.fstat(handle.fileno())
        if not stat.S_ISREG(metadata.st_mode):
            raise OSError("device_key_lock_invalid")
        if os.name != "nt" and (metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) & 0o077):
            raise PermissionError("device_key_acl_invalid")
        try:
            _acquire_lock(handle)
        except OSError as exc:
            raise BlockingIOError("device_key_operation_in_progress") from exc
        try:
            yield
        finally:
            _release_lock(handle)


def _parse_generation(raw: object) -> KeyGeneration | None:
    if raw is None:
        return None
    if not isinstance(raw, dict):
        raise ValueError("device_key_metadata_invalid")
    generation = raw.get("generation")
    key_id = raw.get("keyId")
    public_key_spki = raw.get("publicKeySpki")
    protection_level = raw.get("protectionLevel")
    created_at = raw.get("createdAt")
    if (
        not isinstance(generation, str)
        or len(generation) != 32
        or any(character not in "0123456789abcdef" for character in generation)
        or not isinstance(key_id, str)
        or not key_id
        or not isinstance(public_key_spki, str)
        or len(public_key_spki) > 1024
        or protection_level not in {"hardware-backed", "os-protected"}
        or not isinstance(created_at, str)
        or not created_at
    ):
        raise ValueError("device_key_metadata_invalid")
    return KeyGeneration(
        generation,
        key_id,
        public_key_spki,
        cast(KeyProtectionLevel, protection_level),
        created_at,
    )


def _read_metadata(paths: MachinePaths) -> DeviceKeyMetadata | None:
    try:
        raw = json.loads(_bounded_private_file(_metadata_path(paths)))
    except FileNotFoundError:
        return None
    if not isinstance(raw, dict) or raw.get("schemaVersion") != _METADATA_SCHEMA:
        raise ValueError("device_key_metadata_invalid")
    state = raw.get("state")
    pending = raw.get("pendingGeneration")
    updated_at = raw.get("updatedAt")
    if (
        state not in {"pending", "active", "rotation_pending", "revoked"}
        or (
            pending is not None
            and (
                not isinstance(pending, str)
                or len(pending) != 32
                or any(character not in "0123456789abcdef" for character in pending)
            )
        )
        or not isinstance(updated_at, str)
        or not updated_at
    ):
        raise ValueError("device_key_metadata_invalid")
    metadata = DeviceKeyMetadata(
        cast(LifecycleState, state),
        _parse_generation(raw.get("active")),
        cast(str | None, pending),
        _parse_generation(raw.get("previous")),
        updated_at,
    )
    if metadata.state == "active" and (metadata.active is None or metadata.pending_generation is not None):
        raise ValueError("device_key_metadata_invalid")
    if metadata.state in {"pending", "rotation_pending"} and metadata.pending_generation is None:
        raise ValueError("device_key_metadata_invalid")
    return metadata


def _generation_from_evidence(generation: str, evidence: NativeKeyEvidence) -> KeyGeneration:
    if evidence.state != "active" or evidence.public_key_x963 is None:
        raise OSError(evidence.reason_code)
    public_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), evidence.public_key_x963)
    public_der = public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    digest = hashlib.sha256(public_der).digest()
    key_id = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    return KeyGeneration(
        generation,
        key_id,
        base64.b64encode(public_der).decode("ascii"),
        evidence.protection_level,
        _now(),
    )


def require_machine_device_context(system_name: str) -> None:
    if system_name == "Darwin":
        if os.geteuid() != 0:
            raise PermissionError("device_key_system_context_required")
        return
    if system_name == "Windows":
        if _windows_current_user_sid() != _SYSTEM_SID:
            raise PermissionError("device_key_system_context_required")
        return
    raise OSError("device_key_platform_unsupported")


def _verify_generation(paths: MachinePaths, generation: KeyGeneration, system_name: str) -> KeyProtectionStatus:
    evidence = _run_helper(paths, "inspect", generation.generation, system_name=system_name)
    if evidence.state == "absent":
        return KeyProtectionStatus("absent", generation.protection_level, "device_key_absent")
    if evidence.state != "active" or evidence.public_key_x963 is None:
        return KeyProtectionStatus("unknown", generation.protection_level, "device_key_unusable")
    observed = _generation_from_evidence(generation.generation, evidence)
    if (
        observed.key_id != generation.key_id
        or observed.public_key_spki != generation.public_key_spki
        or observed.protection_level != generation.protection_level
    ):
        return KeyProtectionStatus("tampered", generation.protection_level, "device_key_public_mismatch")
    return KeyProtectionStatus("healthy", generation.protection_level, "device_key_active")


def verify_machine_device_key(
    paths: MachinePaths,
    *,
    system_name: str | None = None,
) -> KeyProtectionStatus:
    """Perform bounded live proof-of-possession for the active machine key."""

    resolved_system = system_name or platform.system()
    if resolved_system not in {"Darwin", "Windows"}:
        return KeyProtectionStatus("unsupported", "unavailable", "device_key_platform_unsupported")
    try:
        metadata = _read_metadata(paths)
        if metadata is None:
            return KeyProtectionStatus("absent", "unavailable", "device_key_absent")
        if metadata.state == "revoked":
            generations = [item.generation for item in (metadata.active, metadata.previous) if item is not None]
            if metadata.pending_generation is not None:
                generations.append(metadata.pending_generation)
            for generation in generations:
                evidence = _run_helper(paths, "inspect", generation, system_name=resolved_system)
                if evidence.state != "absent":
                    return KeyProtectionStatus("degraded", "unknown", "device_key_revocation_incomplete")
            return KeyProtectionStatus("absent", "unavailable", "device_key_revoked")
        if metadata.state in {"pending", "rotation_pending"}:
            return KeyProtectionStatus("degraded", "unknown", "device_key_rotation_incomplete")
        if metadata.active is None:
            return KeyProtectionStatus("tampered", "unknown", "device_key_metadata_invalid")
        return _verify_generation(paths, metadata.active, resolved_system)
    except PermissionError:
        return KeyProtectionStatus("tampered", "unknown", "device_key_acl_invalid")
    except (OSError, subprocess.SubprocessError):
        return KeyProtectionStatus("unknown", "unknown", "device_key_probe_failed")
    except (ValueError, json.JSONDecodeError):
        return KeyProtectionStatus("tampered", "unknown", "device_key_metadata_invalid")


def verified_machine_device_key_ids(
    paths: MachinePaths,
    *,
    system_name: str | None = None,
) -> tuple[str, frozenset[str]]:
    resolved_system = system_name or platform.system()
    if resolved_system not in {"Darwin", "Windows"}:
        raise OSError("device_key_platform_unsupported")
    metadata = _read_metadata(paths)
    if metadata is None:
        raise OSError("device_key_absent")
    if metadata.state != "active" or metadata.active is None:
        raise OSError("device_key_rotation_incomplete" if metadata.state != "revoked" else "device_key_revoked")
    verified: set[str] = set()
    for generation in (metadata.active, metadata.previous):
        if generation is None:
            continue
        status = _verify_generation(paths, generation, resolved_system)
        if status.healthy:
            verified.add(generation.key_id)
        elif generation is metadata.active:
            raise OSError(status.reason_code)
    return metadata.active.key_id, frozenset(verified)


def machine_device_key_status() -> KeyProtectionStatus:
    """Return live device-key status from a privileged machine context."""

    system_name = platform.system()
    require_machine_device_context(system_name)
    return verify_machine_device_key(default_machine_paths(system_name=system_name), system_name=system_name)


def _public_result(operation: str, metadata: DeviceKeyMetadata, status: KeyProtectionStatus) -> dict[str, object]:
    active = metadata.active
    return {
        "schemaVersion": "hol-guard-mdm-status.v1",
        "operation": operation,
        "healthy": status.healthy,
        "state": status.state,
        "keyId": active.key_id if active is not None else None,
        "publicKeySpki": active.public_key_spki if active is not None else None,
        "protectionLevel": status.level,
        "reasonCodes": [status.reason_code],
    }


def _activate_pending(paths: MachinePaths, metadata: DeviceKeyMetadata, *, system_name: str) -> DeviceKeyMetadata:
    generation = metadata.pending_generation
    if generation is None:
        raise OSError("device_key_metadata_invalid")
    evidence = _run_helper(paths, "inspect", generation, system_name=system_name)
    if evidence.state == "absent":
        evidence = _run_helper(paths, "create", generation, system_name=system_name)
    active = _generation_from_evidence(generation, evidence)
    updated = DeviceKeyMetadata("active", active, None, metadata.active, _now())
    _atomic_metadata_write(paths, updated)
    return updated


def provision_machine_device_key() -> dict[str, object]:
    """Idempotently create or recover the machine device key."""

    system_name = platform.system()
    require_machine_device_context(system_name)
    paths = default_machine_paths(system_name=system_name)
    with _machine_key_lock(paths):
        metadata = _read_metadata(paths)
        if metadata is not None and metadata.state == "active" and metadata.active is not None:
            return _public_result(
                "device-key-provision",
                metadata,
                _verify_generation(paths, metadata.active, system_name),
            )
        if metadata is not None and metadata.state == "revoked":
            raise OSError("device_key_revoked")
        if metadata is None:
            metadata = DeviceKeyMetadata("pending", None, secrets.token_hex(16), None, _now())
            _atomic_metadata_write(paths, metadata)
        metadata = _activate_pending(paths, metadata, system_name=system_name)
        return _public_result(
            "device-key-provision",
            metadata,
            _verify_generation(paths, cast(KeyGeneration, metadata.active), system_name),
        )


def rotate_machine_device_key() -> dict[str, object]:
    """Journal and activate a new generation while retaining the prior public identity."""

    system_name = platform.system()
    require_machine_device_context(system_name)
    paths = default_machine_paths(system_name=system_name)
    with _machine_key_lock(paths):
        metadata = _read_metadata(paths)
        if metadata is None or metadata.active is None or metadata.state == "revoked":
            raise OSError("device_key_active_key_required")
        # The retained key may anchor installation continuity. Only a future authenticated
        # Cloud acknowledgement may migrate that binding before retirement or another rotation.
        if metadata.previous is not None and metadata.state != "rotation_pending":
            raise OSError("device_key_previous_generation_pending")
        if metadata.state != "rotation_pending":
            metadata = DeviceKeyMetadata(
                "rotation_pending",
                metadata.active,
                secrets.token_hex(16),
                metadata.previous,
                _now(),
            )
            _atomic_metadata_write(paths, metadata)
        metadata = _activate_pending(paths, metadata, system_name=system_name)
        return _public_result(
            "device-key-rotate",
            metadata,
            _verify_generation(paths, cast(KeyGeneration, metadata.active), system_name),
        )


def revoke_machine_device_key() -> dict[str, object]:
    """Disable signing first, then idempotently remove every retained native generation."""

    system_name = platform.system()
    require_machine_device_context(system_name)
    paths = default_machine_paths(system_name=system_name)
    with _machine_key_lock(paths):
        metadata = _read_metadata(paths)
        if metadata is None:
            raise OSError("device_key_absent")
        if metadata.state != "revoked":
            metadata = DeviceKeyMetadata(
                "revoked",
                metadata.active,
                metadata.pending_generation,
                metadata.previous,
                _now(),
            )
            _atomic_metadata_write(paths, metadata)
        generations = {item.generation for item in (metadata.active, metadata.previous) if item is not None}
        if metadata.pending_generation is not None:
            generations.add(metadata.pending_generation)
        for generation in sorted(generations):
            evidence = _run_helper(paths, "delete", generation, system_name=system_name)
            if evidence.state != "absent":
                raise OSError("device_key_revocation_incomplete")
        status = verify_machine_device_key(paths, system_name=system_name)
        return _public_result("device-key-revoke", metadata, status)


__all__ = [
    "DeviceKeyMetadata",
    "KeyGeneration",
    "machine_device_key_status",
    "provision_machine_device_key",
    "require_machine_device_context",
    "revoke_machine_device_key",
    "rotate_machine_device_key",
    "verified_machine_device_key_ids",
    "verify_machine_device_key",
]
