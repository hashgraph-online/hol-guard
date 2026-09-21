"""Linux executable digest reuse bound to an already attested live child.

This module never authorizes a process launch. A new child always needs fresh
full-byte admission, even when another child pins the same executable. Linux
rejects writes to a running executable (ETXTBSY); a live process, its start
marker, image inode, and a local filesystem establish the retained image proof.
Path/stat information alone is only an invalidation hint and is never a proof.
Other platforms and filesystem types retain full validation.
"""

from __future__ import annotations

import errno
import hashlib
import os
import stat
import subprocess
import sys
import threading
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Literal

if TYPE_CHECKING:
    from .native_runtime import NativeRuntimeIdentity, NativeRuntimeStatus

_LOCAL_EXECUTABLE_FILESYSTEMS = frozenset({"ext2", "ext3", "ext4", "xfs", "btrfs", "tmpfs"})
_MAX_MOUNTINFO_BYTES = 1024 * 1024
_MAX_MANIFEST_BYTES = 16 * 1024
_MAX_ATTESTATIONS = 256
_LOCK = threading.Lock()
_digest_reuse_suspended = False


@dataclass(frozen=True)
class NativeProcessAttestation:
    """An exact child/image proof, consumed only by that existing child."""

    process: subprocess.Popen[bytes]
    identity: NativeRuntimeIdentity
    image_metadata: tuple[int, ...]
    process_start_marker: str
    package_version: str
    manifest_binding: tuple[tuple[int, ...], bytes]


_ATTESTATIONS: dict[int, NativeProcessAttestation] = {}
# These entries grant no trust. They prevent another child on the same path
# from enabling digest reuse while an uninspectable client is still live.
_FULL_VALIDATION_CLIENTS: dict[int, tuple[subprocess.Popen[bytes], Path]] = {}


@dataclass(frozen=True)
class NativeProcessAttestationResult:
    status: Literal["verified", "unsupported", "invalid"]
    attestation: NativeProcessAttestation | None = None


@dataclass(frozen=True)
class NativeProcessImageInspection:
    status: Literal["verified", "unsupported", "invalid"]
    path_metadata: tuple[int, ...] | None = None
    process_start_marker: str | None = None


def _metadata_binding(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def runtime_pool_generation_hint(executable: Path) -> tuple[tuple[int, ...] | None, ...]:
    """Retire a pool when its files change; this hint grants no authority."""

    result: list[tuple[int, ...] | None] = []
    for path in (executable, executable.with_name("runtime-manifest.json")):
        try:
            result.append(_metadata_binding(path.lstat()))
        except OSError:
            result.append(None)
    return tuple(result)


def _manifest_binding(executable: Path) -> tuple[tuple[int, ...], bytes] | None:
    path = executable.with_name("runtime-manifest.json")
    try:
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= _MAX_MANIFEST_BYTES:
            return None
        with path.open("rb") as stream:
            content = stream.read(_MAX_MANIFEST_BYTES + 1)
        after = path.lstat()
        if len(content) > _MAX_MANIFEST_BYTES or _metadata_binding(before) != _metadata_binding(after):
            return None
        return _metadata_binding(after), hashlib.sha256(content).digest()
    except (OSError, RuntimeError, ValueError):
        return None


def _inspect_process_image(process: subprocess.Popen[bytes], executable: Path) -> NativeProcessImageInspection:
    """Separate an unavailable kernel interface from observed bad identity.

    Only errors from /proc inspection can be unsupported. Missing/unsafe
    installation metadata and affirmative process/image mismatches are invalid.
    """

    try:
        if process.poll() is not None:
            return NativeProcessImageInspection("invalid")
        lexical = executable.lstat()
        if (
            not stat.S_ISREG(lexical.st_mode)
            or stat.S_IMODE(lexical.st_mode) & 0o022
            or lexical.st_uid not in {0, os.getuid()}
        ):
            return NativeProcessImageInspection("invalid")
        metadata = _metadata_binding(lexical)
    except (OSError, RuntimeError, ValueError):
        return NativeProcessImageInspection("invalid")
    start_marker: str | None = None
    try:
        proc = Path("/proc") / str(process.pid)
        process_stat = (proc / "stat").read_text(encoding="ascii")
        prefix, suffix = process_stat.rsplit(")", 1)
        fields = suffix.split()
        if (
            prefix.split("(", 1)[0].strip() != str(process.pid)
            or len(fields) < 20
            or fields[0] in {"Z", "X", "x"}
            or fields[1] != str(os.getpid())
            or not fields[19].isdigit()
        ):
            return NativeProcessImageInspection("invalid")
        start_marker = fields[19]
        image = (proc / "exe").stat()
        if not stat.S_ISREG(image.st_mode) or metadata != _metadata_binding(image) or process.poll() is not None:
            return NativeProcessImageInspection("invalid")
        return NativeProcessImageInspection("verified", metadata, start_marker)
    except OSError as error:
        unsupported_errors = {errno.EACCES, errno.EPERM, errno.ENOENT, errno.ENOSYS, errno.ENOTSUP}
        if error.errno in unsupported_errors and process.poll() is None:
            return NativeProcessImageInspection("unsupported", metadata, start_marker)
        return NativeProcessImageInspection("invalid")
    except (RuntimeError, ValueError):
        return NativeProcessImageInspection("invalid")


def _process_image(process: subprocess.Popen[bytes], executable: Path) -> tuple[tuple[int, ...], str] | None:
    inspected = _inspect_process_image(process, executable)
    if inspected.status != "verified" or inspected.path_metadata is None or inspected.process_start_marker is None:
        return None
    return inspected.path_metadata, inspected.process_start_marker


def _prune_finished_clients_locked() -> None:
    for key, item in tuple(_ATTESTATIONS.items()):
        if item.process.poll() is not None:
            _ = _ATTESTATIONS.pop(key, None)
    for key, (process, _) in tuple(_FULL_VALIDATION_CLIENTS.items()):
        if process.poll() is not None:
            _ = _FULL_VALIDATION_CLIENTS.pop(key, None)


def _has_full_validation_client_locked(executable: Path) -> bool:
    for key, (process, path) in tuple(_FULL_VALIDATION_CLIENTS.items()):
        if path != executable:
            continue
        if process.poll() is None:
            return True
        _ = _FULL_VALIDATION_CLIENTS.pop(key, None)
    return False


def _registry_slot_available_locked(process: subprocess.Popen[bytes]) -> bool:
    """Capacity failure disables reuse, never ordinary full admission.

    An untracked live client cannot permit indirect reuse. A process-lifetime
    latch provides that guarantee without an unbounded overflow registry.
    """

    global _digest_reuse_suspended
    _prune_finished_clients_locked()
    if _digest_reuse_suspended:
        return False
    if id(process) in _ATTESTATIONS or id(process) in _FULL_VALIDATION_CLIENTS:
        return True
    if len(_ATTESTATIONS) + len(_FULL_VALIDATION_CLIENTS) >= _MAX_ATTESTATIONS:
        _digest_reuse_suspended = True
        return False
    return True


def _local_executable_filesystem(process: subprocess.Popen[bytes]) -> bool:
    """Use the opened image's mount ID, not a guessed path-prefix mount."""

    try:
        with (Path("/proc") / str(process.pid) / "exe").open("rb") as image:
            descriptor_info = (Path("/proc/self/fdinfo") / str(image.fileno())).read_text(encoding="ascii")
            mount_id = next(
                (line.split(":", 1)[1].strip() for line in descriptor_info.splitlines() if line.startswith("mnt_id:")),
                None,
            )
            if mount_id is None:
                return False
            with Path("/proc/self/mountinfo").open("rb") as mounts:
                content = mounts.read(_MAX_MOUNTINFO_BYTES + 1)
            if len(content) > _MAX_MOUNTINFO_BYTES:
                return False
            for line in content.decode("utf-8", errors="strict").splitlines():
                if line.split(" ", 1)[0] != mount_id:
                    continue
                _, separator, filesystem = line.partition(" - ")
                return bool(separator) and filesystem.split(" ", 1)[0] in _LOCAL_EXECUTABLE_FILESYSTEMS
    except (OSError, RuntimeError, ValueError):
        return False
    return False


def attest_native_process(
    process: subprocess.Popen[bytes],
    expected: NativeRuntimeStatus,
    *,
    verify: Callable[[], NativeRuntimeStatus],
    package_version: Callable[[], str | None],
) -> NativeProcessAttestationResult:
    """Hash again while the actual child pins the executable, then register it.

    Unsupported local proof retains full validation. A failed identity proof is
    distinct: the caller must close that child before writing any hook frame.
    """

    if sys.platform != "linux" or expected.identity is None or expected.capabilities is None:
        return NativeProcessAttestationResult("unsupported")
    if not expected.available or not expected.compatible:
        return NativeProcessAttestationResult("invalid")
    executable = expected.identity.path
    before = _inspect_process_image(process, executable)
    if before.status == "invalid":
        return NativeProcessAttestationResult("invalid")
    reusable_filesystem = before.status == "verified" and _local_executable_filesystem(process)
    manifest = _manifest_binding(executable)
    verified = verify()
    after = _inspect_process_image(process, executable)
    version = package_version()
    if (
        after.status == "invalid"
        or before.path_metadata != after.path_metadata
        or (
            before.process_start_marker is not None
            and after.process_start_marker is not None
            and before.process_start_marker != after.process_start_marker
        )
        or manifest is None
        or manifest != _manifest_binding(executable)
        or verified != expected
        or version != expected.capabilities.runtime_version
        or process.poll() is not None
    ):
        return NativeProcessAttestationResult("invalid")
    if not reusable_filesystem or after.status != "verified":
        # A full pre-launch and post-launch validation remains authoritative
        # when the kernel cannot expose image/start proof. Never cache that
        # ambiguity, including indirectly through another child on this path.
        with _LOCK:
            if not _registry_slot_available_locked(process):
                return NativeProcessAttestationResult("unsupported")
            _ = _ATTESTATIONS.pop(id(process), None)
            _FULL_VALIDATION_CLIENTS[id(process)] = (process, executable)
        return NativeProcessAttestationResult("unsupported")
    assert version is not None
    assert before.path_metadata is not None and before.process_start_marker is not None
    attestation = NativeProcessAttestation(
        process, expected.identity, before.path_metadata, before.process_start_marker, version, manifest
    )
    with _LOCK:
        if not _registry_slot_available_locked(process):
            return NativeProcessAttestationResult("unsupported")
        _ = _FULL_VALIDATION_CLIENTS.pop(id(process), None)
        _ATTESTATIONS[id(process)] = attestation
    return NativeProcessAttestationResult("verified", attestation)


def attestation_is_current(attestation: NativeProcessAttestation, *, package_version: str | None) -> bool:
    with _LOCK:
        registered = _ATTESTATIONS.get(id(attestation.process)) is attestation
    if not (
        registered
        and package_version == attestation.package_version
        and _process_image(attestation.process, attestation.identity.path)
        == (attestation.image_metadata, attestation.process_start_marker)
        and _manifest_binding(attestation.identity.path) == attestation.manifest_binding
    ):
        return False
    # File probes may run concurrently with retirement. This final registry
    # check is the success linearization point; no IO runs under the lock.
    with _LOCK:
        return _ATTESTATIONS.get(id(attestation.process)) is attestation


def live_native_identity(
    executable: Path, *, package_version: Callable[[], str | None]
) -> NativeRuntimeIdentity | None:
    if sys.platform != "linux":
        return None
    with _LOCK:
        if _digest_reuse_suspended or _has_full_validation_client_locked(executable):
            return None
        candidates = tuple(item for item in _ATTESTATIONS.values() if item.identity.path == executable)
    if not candidates:
        return None
    version = package_version()
    for candidate in candidates:
        if attestation_is_current(candidate, package_version=version):
            # A non-reusable client may register while file probes run.
            with _LOCK:
                if (
                    _ATTESTATIONS.get(id(candidate.process)) is candidate
                    and not _digest_reuse_suspended
                    and not _has_full_validation_client_locked(executable)
                ):
                    return candidate.identity
            return None
        with _LOCK:
            # A concurrent full-validation registration for this process must
            # keep its path blocker even when an older attestation is stale.
            if _ATTESTATIONS.get(id(candidate.process)) is candidate:
                _ = _ATTESTATIONS.pop(id(candidate.process), None)
    return None


def retire_native_process(process: subprocess.Popen[bytes]) -> None:
    with _LOCK:
        _ = _ATTESTATIONS.pop(id(process), None)
        _ = _FULL_VALIDATION_CLIENTS.pop(id(process), None)


def retire_native_path(executable: Path) -> None:
    with _LOCK:
        for key in tuple(key for key, item in _ATTESTATIONS.items() if item.identity.path == executable):
            _ATTESTATIONS.pop(key, None)
