"""Protected installation identity and read-only lease-continuity evidence."""

from __future__ import annotations

import ctypes
import errno
import json
import os
import platform
import secrets
import stat
import time
import uuid
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import BinaryIO, Literal

from .contracts import MachinePaths, default_machine_paths
from .device_key import require_machine_device_context, verified_machine_device_key_ids

_SCHEMA = "hol-guard-installation-continuity.v1"
_STATE_NAME = "installation-continuity.json"
_LOCK_NAME = ".installation-continuity.lock"
_MAX_STATE_BYTES = 64 * 1024
_MAX_UINT64 = (1 << 64) - 1

ContinuityState = Literal["healthy", "degraded", "absent", "tampered", "unknown", "unsupported"]


@dataclass(frozen=True, slots=True)
class InstallationContinuityRecord:
    machine_installation_id: str
    installation_generation: str
    generation_created_at: str
    key_id_at_generation_creation: str
    last_issued_sequence: int
    last_lease_digest: str | None
    last_lease_boot_session_id: str | None
    last_lease_monotonic_uptime_ns: int | None
    updated_at: str
    last_lease_key_id: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "schemaVersion": _SCHEMA,
            "machineInstallationId": self.machine_installation_id,
            "installationGeneration": self.installation_generation,
            "generationCreatedAt": self.generation_created_at,
            "keyIdAtGenerationCreation": self.key_id_at_generation_creation,
            "lastIssuedSequence": self.last_issued_sequence,
            "lastLeaseDigest": self.last_lease_digest,
            "lastLeaseBootSessionId": self.last_lease_boot_session_id,
            "lastLeaseMonotonicUptimeNs": self.last_lease_monotonic_uptime_ns,
            "lastLeaseKeyId": self.last_lease_key_id,
            "updatedAt": self.updated_at,
        }


@dataclass(frozen=True, slots=True)
class BootObservation:
    boot_session_id: str
    monotonic_uptime_ns: int


@dataclass(frozen=True, slots=True)
class ContinuityVerification:
    state: ContinuityState
    identity_reason_code: str
    lease_reason_code: str
    record: InstallationContinuityRecord | None = None
    observation: BootObservation | None = None

    @property
    def healthy(self) -> bool:
        return self.state == "healthy"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _state_path(paths: MachinePaths) -> Path:
    return paths.state_root / _STATE_NAME


def _lock_path(paths: MachinePaths) -> Path:
    return paths.state_root / _LOCK_NAME


def _private_regular_file(metadata: os.stat_result) -> bool:
    if not stat.S_ISREG(metadata.st_mode):
        return False
    return os.name == "nt" or (metadata.st_uid == 0 and not stat.S_IMODE(metadata.st_mode) & 0o077)


def _bounded_private_file(path: Path) -> bytes:
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0))
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise PermissionError("installation_identity_acl_invalid") from exc
        raise
    try:
        before = os.fstat(descriptor)
        if before.st_size > _MAX_STATE_BYTES or not _private_regular_file(before):
            raise PermissionError("installation_identity_acl_invalid")
        payload = os.read(descriptor, _MAX_STATE_BYTES + 1)
        after = os.fstat(descriptor)
        before_identity = (before.st_dev, before.st_ino, before.st_size, before.st_ctime_ns)
        after_identity = (after.st_dev, after.st_ino, after.st_size, after.st_ctime_ns)
        if len(payload) > _MAX_STATE_BYTES or len(payload) != before.st_size or before_identity != after_identity:
            raise OSError("installation_identity_invalid")
        return payload
    finally:
        os.close(descriptor)


def _hex_string(value: object, length: int) -> str:
    if not isinstance(value, str) or len(value) != length or any(char not in "0123456789abcdef" for char in value):
        raise ValueError("installation_identity_invalid")
    return value


def _timestamp(value: object) -> str:
    if not isinstance(value, str) or len(value) > 64:
        raise ValueError("installation_identity_invalid")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ValueError("installation_identity_invalid") from exc
    if parsed.tzinfo is None:
        raise ValueError("installation_identity_invalid")
    return value


def _optional_bounded_string(value: object, *, length: int | None = None) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value or len(value) > 256:
        raise ValueError("installation_identity_invalid")
    if length is not None:
        return _hex_string(value, length)
    return value


def _uint64(value: object) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0 or value > _MAX_UINT64:
        raise ValueError("installation_identity_invalid")
    return value


def _parse_record(payload: bytes) -> InstallationContinuityRecord:
    try:
        raw = json.loads(payload)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ValueError("installation_identity_invalid") from exc
    if not isinstance(raw, dict) or raw.get("schemaVersion") != _SCHEMA:
        raise ValueError("installation_identity_invalid")
    sequence = _uint64(raw.get("lastIssuedSequence"))
    digest = _optional_bounded_string(raw.get("lastLeaseDigest"), length=64)
    boot_id = _optional_bounded_string(raw.get("lastLeaseBootSessionId"))
    uptime_raw = raw.get("lastLeaseMonotonicUptimeNs")
    uptime = None if uptime_raw is None else _uint64(uptime_raw)
    lease_key_id = _optional_bounded_string(raw.get("lastLeaseKeyId"))
    if sequence == 0 and any(value is not None for value in (digest, boot_id, uptime, lease_key_id)):
        raise ValueError("installation_identity_invalid")
    if sequence > 0 and any(value is None for value in (digest, boot_id, uptime, lease_key_id)):
        raise ValueError("installation_identity_invalid")
    key_id = raw.get("keyIdAtGenerationCreation")
    if not isinstance(key_id, str) or not key_id or len(key_id) > 256:
        raise ValueError("installation_identity_invalid")
    return InstallationContinuityRecord(
        _hex_string(raw.get("machineInstallationId"), 32),
        _hex_string(raw.get("installationGeneration"), 32),
        _timestamp(raw.get("generationCreatedAt")),
        key_id,
        sequence,
        digest,
        boot_id,
        uptime,
        _timestamp(raw.get("updatedAt")),
        lease_key_id,
    )


def _read_record(paths: MachinePaths) -> InstallationContinuityRecord | None:
    try:
        return _parse_record(_bounded_private_file(_state_path(paths)))
    except FileNotFoundError:
        return None


def _atomic_write(paths: MachinePaths, record: InstallationContinuityRecord) -> None:
    parent = paths.state_root
    if parent.is_symlink() or not parent.is_dir():
        raise OSError("installation_identity_state_root_invalid")
    target = _state_path(paths)
    temporary = parent / f".{target.name}.{secrets.token_hex(16)}.tmp"
    payload = json.dumps(record.to_dict(), sort_keys=True, separators=(",", ":")).encode("utf-8")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, target)
        if os.name != "nt":
            parent_descriptor = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(parent_descriptor)
            finally:
                os.close(parent_descriptor)
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
def _continuity_lock(paths: MachinePaths) -> Iterator[None]:
    if paths.state_root.is_symlink() or not paths.state_root.is_dir():
        raise OSError("installation_identity_state_root_invalid")
    descriptor = os.open(
        _lock_path(paths),
        os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    with os.fdopen(descriptor, "r+b", closefd=True) as handle:
        metadata = os.fstat(handle.fileno())
        if not _private_regular_file(metadata):
            raise PermissionError("installation_identity_acl_invalid")
        try:
            _acquire_lock(handle)
        except OSError as exc:
            raise BlockingIOError("installation_identity_operation_in_progress") from exc
        try:
            yield
        finally:
            _release_lock(handle)


def _validated_boot_session_id(value: str) -> str:
    normalized = value.strip()
    if not normalized or len(normalized) > 256 or not normalized.strip("0-{}"):
        raise OSError("lease_continuity_boot_probe_failed")
    return normalized


def _darwin_boot_observation() -> BootObservation:
    libc = ctypes.CDLL(None, use_errno=True)
    size = ctypes.c_size_t(0)
    if libc.sysctlbyname(b"kern.bootsessionuuid", None, ctypes.byref(size), None, 0) != 0 or size.value > 256:
        raise OSError("lease_continuity_boot_probe_failed")
    buffer = ctypes.create_string_buffer(size.value)
    if libc.sysctlbyname(b"kern.bootsessionuuid", buffer, ctypes.byref(size), None, 0) != 0:
        raise OSError("lease_continuity_boot_probe_failed")
    boot_session_id = _validated_boot_session_id(buffer.value.decode("ascii"))

    class Timebase(ctypes.Structure):
        _fields_ = [("numer", ctypes.c_uint32), ("denom", ctypes.c_uint32)]

    timebase = Timebase()
    if libc.mach_timebase_info(ctypes.byref(timebase)) != 0 or timebase.denom == 0:
        raise OSError("lease_continuity_monotonic_probe_failed")
    libc.mach_continuous_time.restype = ctypes.c_uint64
    uptime = libc.mach_continuous_time() * timebase.numer // timebase.denom
    return BootObservation(boot_session_id, uptime)


def _windows_boot_observation() -> BootObservation:
    class Guid(ctypes.Structure):
        _fields_ = [
            ("data1", ctypes.c_uint32),
            ("data2", ctypes.c_uint16),
            ("data3", ctypes.c_uint16),
            ("data4", ctypes.c_ubyte * 8),
        ]

    class BootEnvironment(ctypes.Structure):
        _fields_ = [("identifier", Guid), ("firmware_type", ctypes.c_uint32), ("boot_flags", ctypes.c_uint64)]

    info = BootEnvironment()
    returned = ctypes.c_ulong(0)
    status = ctypes.windll.ntdll.NtQuerySystemInformation(
        90, ctypes.byref(info), ctypes.sizeof(info), ctypes.byref(returned)
    )
    if status != 0:
        raise OSError("lease_continuity_boot_probe_failed")
    raw_guid = bytes(ctypes.string_at(ctypes.byref(info.identifier), ctypes.sizeof(Guid)))
    boot_session_id = _validated_boot_session_id(str(uuid.UUID(bytes_le=raw_guid)))
    get_tick_count = ctypes.windll.kernel32.GetTickCount64
    get_tick_count.restype = ctypes.c_ulonglong
    uptime = int(get_tick_count()) * 1_000_000
    return BootObservation(boot_session_id, uptime)


def observe_boot(*, system_name: str | None = None) -> BootObservation:
    resolved = system_name or platform.system()
    if resolved == "Darwin":
        return _darwin_boot_observation()
    if resolved == "Windows":
        return _windows_boot_observation()
    if resolved == "Linux":
        boot_id = Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip()
        return BootObservation(_validated_boot_session_id(boot_id), time.monotonic_ns())
    raise OSError("lease_continuity_platform_unsupported")


def verify_installation_continuity(
    paths: MachinePaths,
    *,
    system_name: str | None = None,
) -> ContinuityVerification:
    """Read and validate continuity evidence without changing protected state."""

    resolved = system_name or platform.system()
    try:
        record = _read_record(paths)
        if record is None:
            return ContinuityVerification("absent", "installation_identity_absent", "lease_continuity_absent")
        _, verified_ids = verified_machine_device_key_ids(paths, system_name=resolved)
        if record.key_id_at_generation_creation not in verified_ids:
            return ContinuityVerification("tampered", "installation_identity_key_mismatch", "lease_continuity_invalid")
        try:
            observation = observe_boot(system_name=resolved)
        except OSError as exc:
            reason = str(exc)
            if reason == "lease_continuity_platform_unsupported":
                return ContinuityVerification("unsupported", "installation_identity_active", reason, record)
            lease_reason = reason if reason.startswith("lease_continuity_") else "lease_continuity_probe_failed"
            return ContinuityVerification("unknown", "installation_identity_active", lease_reason, record)
        if (
            record.last_lease_boot_session_id == observation.boot_session_id
            and record.last_lease_monotonic_uptime_ns is not None
            and observation.monotonic_uptime_ns < record.last_lease_monotonic_uptime_ns
        ):
            return ContinuityVerification(
                "tampered", "installation_identity_active", "lease_continuity_monotonic_regression", record, observation
            )
        if record.last_issued_sequence == _MAX_UINT64:
            return ContinuityVerification(
                "degraded", "installation_identity_active", "lease_continuity_sequence_exhausted", record, observation
            )
        reason = "lease_continuity_uninitialized" if record.last_issued_sequence == 0 else "lease_continuity_active"
        return ContinuityVerification("healthy", "installation_identity_active", reason, record, observation)
    except PermissionError:
        return ContinuityVerification("tampered", "installation_identity_acl_invalid", "lease_continuity_invalid")
    except ValueError:
        return ContinuityVerification("tampered", "installation_identity_invalid", "lease_continuity_invalid")
    except OSError as exc:
        reason = str(exc)
        if reason in {"device_key_absent", "device_key_revoked", "device_key_public_mismatch"}:
            return ContinuityVerification("tampered", "installation_identity_key_mismatch", "lease_continuity_invalid")
        if reason.startswith("device_key_"):
            return ContinuityVerification(
                "unknown", "installation_identity_probe_failed", "lease_continuity_probe_failed"
            )
        return ContinuityVerification("unknown", "installation_identity_probe_failed", "lease_continuity_probe_failed")


def provision_machine_continuity() -> dict[str, object]:
    """Idempotently create protected installation identity after device-key provisioning."""

    system_name = platform.system()
    require_machine_device_context(system_name)
    paths = default_machine_paths(system_name=system_name)
    with _continuity_lock(paths):
        active_key_id, verified_ids = verified_machine_device_key_ids(paths, system_name=system_name)
        record = _read_record(paths)
        if record is not None:
            if record.key_id_at_generation_creation not in verified_ids:
                raise OSError("installation_identity_key_mismatch")
        else:
            now = _now()
            record = InstallationContinuityRecord(
                secrets.token_hex(16), secrets.token_hex(16), now, active_key_id, 0, None, None, None, now
            )
            _atomic_write(paths, record)
        return {
            "schemaVersion": "hol-guard-mdm-status.v1",
            "operation": "continuity-provision",
            "healthy": True,
            "state": "active",
            "machineInstallationId": record.machine_installation_id,
            "installationGeneration": record.installation_generation,
            "sequence": record.last_issued_sequence,
            "reasonCodes": ["installation_identity_active", "lease_continuity_uninitialized"],
        }


__all__ = [
    "BootObservation",
    "ContinuityVerification",
    "InstallationContinuityRecord",
    "observe_boot",
    "provision_machine_continuity",
    "verify_installation_continuity",
]
