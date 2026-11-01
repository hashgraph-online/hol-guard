"""Protected installation identity and read-only lease-continuity evidence.

The native runtime reads, parses and writes the continuity record and decides
what a verification reports. This module keeps the device-key lookup, the
boot probe and the lock.
"""

from __future__ import annotations

import base64
import ctypes
import json
import os
import platform
import secrets
import stat
import time
import uuid
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal, cast, get_args

from .contracts import MachinePaths, default_machine_paths
from .device_key import require_machine_device_context, verified_machine_device_key_ids
from .file_lock import (
    acquire_file_lock as _acquire_lock,
)
from .file_lock import (
    release_file_lock as _release_lock,
)
from .runtime_request import runtime_answer
from .state_file import read_state, replace_state

_SCHEMA = "hol-guard-installation-continuity.v1"
_LOCK_NAME = ".installation-continuity.lock"
_MAX_UINT64 = (1 << 64) - 1
INSTALLATION_CONTINUITY_FEATURE = "native-installation-continuity-v1"
INSTALLATION_CONTINUITY_COMMAND = "installation-continuity"
INSTALLATION_CONTINUITY_SCHEMA = "installation-continuity.v1"
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


def _lock_path(paths: MachinePaths) -> Path:
    return paths.state_root / _LOCK_NAME


def _private_regular_file(metadata: os.stat_result) -> bool:
    if not stat.S_ISREG(metadata.st_mode):
        return False
    return os.name == "nt" or (metadata.st_uid == 0 and not stat.S_IMODE(metadata.st_mode) & 0o077)


def _native_answer(request: dict[str, object]) -> dict[str, Any]:
    """The runtime's answer to one continuity request, with any record as the dataclass."""

    answer = runtime_answer(
        INSTALLATION_CONTINUITY_FEATURE,
        INSTALLATION_CONTINUITY_COMMAND,
        {"schema": INSTALLATION_CONTINUITY_SCHEMA, **request},
        timeout_seconds=_COMMAND_TIMEOUT_SECONDS,
        output_limit=_OUTPUT_LIMIT_BYTES,
    )
    if answer is None or not isinstance(answer.get("ok"), bool):
        # A record nothing could check is never read as active continuity.
        raise OSError("installation_identity_native_unavailable")
    fields = cast(dict[str, Any], answer)
    if isinstance(fields.get("record"), dict):
        try:
            fields["record"] = InstallationContinuityRecord(**cast(dict[str, Any], fields["record"]))
        except TypeError as exc:
            raise OSError("installation_identity_native_unavailable") from exc
    return fields


def _parse_record(payload: bytes) -> InstallationContinuityRecord:
    answer = _native_answer({"op": "parse", "content": base64.b64encode(payload).decode("ascii")})
    if answer["ok"] is not True:
        raise ValueError("installation_identity_invalid")
    record = answer.get("record")
    if not isinstance(record, InstallationContinuityRecord):
        raise OSError("installation_identity_native_unavailable")
    return record


def _read_record(paths: MachinePaths) -> InstallationContinuityRecord | None:
    content = read_state(paths.state_root, "continuity")
    return None if content is None else _parse_record(content)


def _atomic_write(paths: MachinePaths, record: InstallationContinuityRecord) -> None:
    payload = json.dumps(record.to_dict(), sort_keys=True, separators=(",", ":")).encode("utf-8")
    replace_state(paths.state_root, "continuity", payload)


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
        content = read_state(paths.state_root, "continuity")
    except PermissionError:
        return ContinuityVerification("tampered", "installation_identity_acl_invalid", "lease_continuity_invalid")
    except OSError:
        return probe_failed
    if content is None:
        return ContinuityVerification("absent", "installation_identity_absent", "lease_continuity_absent")
    encoded = base64.b64encode(content).decode("ascii")
    try:
        # A record the runtime cannot read never costs a key or boot probe.
        parsed = _native_answer({"op": "parse", "content": encoded})
    except OSError:
        return probe_failed
    if parsed["ok"] is not True:
        return ContinuityVerification("tampered", "installation_identity_invalid", "lease_continuity_invalid")
    observations: list[BootObservation] = []

    def boot() -> dict[str, object]:
        observations.append(observe_boot(system_name=resolved))
        return asdict(observations[0])

    request: dict[str, object] = {
        "op": "verify",
        "content": encoded,
        "key": _probe(lambda: {"ids": sorted(verified_machine_device_key_ids(paths, system_name=resolved)[1])}),
        "boot": _probe(boot),
    }
    try:
        answer = _native_answer(request)
        state = answer["state"]
        identity_reason = answer["identity_reason_code"]
        lease_reason = answer["lease_reason_code"]
        record = answer.get("record")
        observed = answer["observed"] is True and bool(observations)
    except (OSError, KeyError):
        return probe_failed
    if not (
        state in get_args(ContinuityState)
        and isinstance(identity_reason, str)
        and isinstance(lease_reason, str)
        and (record is None or isinstance(record, InstallationContinuityRecord))
    ):
        return probe_failed
    return ContinuityVerification(
        cast(ContinuityState, state), identity_reason, lease_reason, record, observations[0] if observed else None
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
