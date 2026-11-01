"""Protected installation identity and read-only lease-continuity evidence.

The native runtime reads, parses and writes the continuity record, observes
the boot and decides what a verification reports. This module keeps the
device-key lookup and the lock.
"""

from __future__ import annotations

import base64
import json
import os
import platform
import secrets
import stat
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
BOOT_OBSERVATION_FEATURE = "native-boot-observation-v1"
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


def _native_answer(request: dict[str, object], *, extra_features: tuple[str, ...] = ()) -> dict[str, Any]:
    """The runtime's answer to one continuity request, with any record as the dataclass."""

    answer = runtime_answer(
        INSTALLATION_CONTINUITY_FEATURE,
        INSTALLATION_CONTINUITY_COMMAND,
        {"schema": INSTALLATION_CONTINUITY_SCHEMA, **request},
        timeout_seconds=_COMMAND_TIMEOUT_SECONDS,
        output_limit=_OUTPUT_LIMIT_BYTES,
        extra_features=extra_features,
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


def observe_boot(*, system_name: str | None = None) -> BootObservation:
    """This boot's session identifier and an uptime that keeps counting through sleep."""

    if (system_name or platform.system()) not in ("Darwin", "Linux", "Windows"):
        raise OSError("lease_continuity_platform_unsupported")
    answer = _native_answer({"op": "observe-boot"}, extra_features=(BOOT_OBSERVATION_FEATURE,))
    if answer["ok"] is not True:
        error = answer.get("error")
        raise OSError(
            error
            if isinstance(error, str) and error.startswith("lease_continuity_")
            else "lease_continuity_probe_failed"
        )
    boot = answer.get("boot")
    if not isinstance(boot, dict):
        raise OSError("lease_continuity_probe_failed")
    session, uptime = boot.get("boot_session_id"), boot.get("monotonic_uptime_ns")
    if not isinstance(session, str) or not session or type(uptime) is not int or uptime < 0:
        raise OSError("lease_continuity_probe_failed")
    return BootObservation(session, uptime)


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
