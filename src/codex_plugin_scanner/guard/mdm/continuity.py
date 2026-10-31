"""Protected installation identity and read-only lease-continuity evidence.

The native runtime parses the continuity record and decides what a
verification reports. This module keeps the privileged reads (the bounded,
owner-checked record read, the device-key lookup and the boot probe), the
lock and the atomic write.
"""

from __future__ import annotations

import base64
import ctypes
import errno
import json
import os
import platform
import secrets
import stat
import time
import uuid
from collections.abc import Callable, Iterator
from contextlib import contextmanager, suppress
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal, cast

from .contracts import MachinePaths, default_machine_paths
from .device_key import require_machine_device_context, verified_machine_device_key_ids
from .file_lock import (
    acquire_file_lock as _acquire_lock,
)
from .file_lock import (
    release_file_lock as _release_lock,
)

_SCHEMA = "hol-guard-installation-continuity.v1"
_STATE_NAME = "installation-continuity.json"
_LOCK_NAME = ".installation-continuity.lock"
_MAX_STATE_BYTES = 64 * 1024
_MAX_UINT64 = (1 << 64) - 1
INSTALLATION_CONTINUITY_FEATURE = "native-installation-continuity-v1"
INSTALLATION_CONTINUITY_COMMAND = "installation-continuity"
INSTALLATION_CONTINUITY_SCHEMA = "installation-continuity.v1"
_STATUS_TIMEOUT_SECONDS = 10.0
_COMMAND_TIMEOUT_SECONDS = 30.0
_OUTPUT_LIMIT_BYTES = 16 * 1024

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


def _native_answer(request: dict[str, object]) -> dict[str, Any]:
    """The runtime's answer to one continuity request, with any record as the dataclass."""

    from ..native_runtime import _run_native_process, native_runtime_status

    status = native_runtime_status(deadline_monotonic=time.monotonic() + _STATUS_TIMEOUT_SECONDS)
    output = None
    if (
        status.available
        and status.compatible
        and status.identity is not None
        and status.capabilities is not None
        and INSTALLATION_CONTINUITY_FEATURE in status.capabilities.features
    ):
        output = _run_native_process(
            status.identity.path,
            (INSTALLATION_CONTINUITY_COMMAND, "--stdin"),
            input_text=json.dumps({"schema": INSTALLATION_CONTINUITY_SCHEMA, **request}, sort_keys=True),
            timeout_seconds=_COMMAND_TIMEOUT_SECONDS,
            output_limit=_OUTPUT_LIMIT_BYTES,
        )
    try:
        answer = cast(object, json.loads(output or ""))
    except ValueError:
        answer = None
    if not isinstance(answer, dict) or not isinstance(cast(dict[str, Any], answer).get("ok"), bool):
        # A record nothing could check is never read as active continuity.
        raise OSError("installation_identity_native_unavailable")
    fields = cast(dict[str, Any], answer)
    if isinstance(fields.get("record"), dict):
        fields["record"] = InstallationContinuityRecord(**cast(dict[str, Any], fields["record"]))
    return fields


def _parse_record(payload: bytes) -> InstallationContinuityRecord:
    answer = _native_answer({"op": "parse", "content": base64.b64encode(payload).decode("ascii")})
    if answer["ok"] is not True:
        raise ValueError("installation_identity_invalid")
    return cast(InstallationContinuityRecord, answer["record"])


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


def _probe(read: Callable[[], dict[str, object]]) -> dict[str, object]:
    """What a probe returned, or the exception it raised for the runtime to map."""

    try:
        return read()
    except PermissionError as exc:
        return {"kind": "permission", "error": str(exc)}
    except ValueError as exc:
        return {"kind": "value", "error": str(exc)}
    except OSError as exc:
        return {"kind": "os", "error": str(exc)}


def verify_installation_continuity(
    paths: MachinePaths,
    *,
    system_name: str | None = None,
) -> ContinuityVerification:
    """Read and validate continuity evidence without changing protected state."""

    resolved = system_name or platform.system()
    probe_failed = ContinuityVerification(
        "unknown", "installation_identity_probe_failed", "lease_continuity_probe_failed"
    )
    try:
        content = _bounded_private_file(_state_path(paths))
    except FileNotFoundError:
        return ContinuityVerification("absent", "installation_identity_absent", "lease_continuity_absent")
    except PermissionError:
        return ContinuityVerification("tampered", "installation_identity_acl_invalid", "lease_continuity_invalid")
    except OSError:
        return probe_failed
    observations: list[BootObservation] = []

    def boot() -> dict[str, object]:
        observations.append(observe_boot(system_name=resolved))
        return asdict(observations[0])

    request: dict[str, object] = {
        "op": "verify",
        "content": base64.b64encode(content).decode("ascii"),
        "key": _probe(lambda: {"ids": sorted(verified_machine_device_key_ids(paths, system_name=resolved)[1])}),
        "boot": _probe(boot),
    }
    try:
        answer = _native_answer(request)
    except OSError:
        return probe_failed
    return ContinuityVerification(
        answer["state"],
        answer["identity_reason_code"],
        answer["lease_reason_code"],
        answer["record"],
        observations[0] if answer["observed"] is True else None,
    )


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
