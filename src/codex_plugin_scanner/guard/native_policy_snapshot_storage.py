"""Durable, canonical native policy snapshot storage and recovery."""

from __future__ import annotations

import hmac
import os
import secrets
import stat
import time
from collections.abc import Iterator, Mapping
from contextlib import ExitStack, contextmanager, suppress
from pathlib import Path
from typing import Any, cast

from . import native_policy_snapshot_storage_windows as _windows_storage
from .native_policy_snapshot_codec import (
    _canonical_json_bytes_v3,
    _generation_floor_mac_v3,
    _strict_json_loads_v3,
    _valid_digest_v3,
)
from .native_policy_snapshot_constants import (
    _MAX_GENERATION,
    _MAX_STATE_BYTES,
    _NATIVE_POLICY_SNAPSHOT_PENDING_NAME,
    _V3_GENERATION_LOCK_NAME,
    _V3_GENERATION_SCHEMA,
    _V3_GENERATION_STATE_NAME,
    NATIVE_POLICY_SNAPSHOT_CACHE_NAME,
    POLICY_SNAPSHOT_AUTHORITY_MAX_BYTES,
    POLICY_SNAPSHOT_AUTHORITY_SCHEMA,
    POLICY_SNAPSHOT_MAX_BYTES,
    NativePolicySnapshotError,
)
from .native_policy_snapshot_contract import (
    snapshot_bytes_v3,
)
from .native_policy_snapshot_windows_support import (
    _runtime_state_directory,
)

_windows_read_generation_state_bytes = _windows_storage._windows_read_generation_state_bytes
_windows_read_snapshot_bytes = _windows_storage._windows_read_snapshot_bytes


def _snapshot_api() -> Any:
    """Resolve façade hooks lazily to preserve the legacy test seams."""

    from . import native_policy_snapshot

    return native_policy_snapshot


def _private_guard_home(guard_home: Path) -> None:
    """Use the façade's established owner/private-home validation seam."""

    from . import native_policy_snapshot

    native_policy_snapshot._private_guard_home(guard_home)


def _snapshot_cache_path_v3(guard_home: Path) -> Path:
    return _runtime_state_directory(guard_home) / NATIVE_POLICY_SNAPSHOT_CACHE_NAME


def _authority_snapshot_v3(
    value: Mapping[str, object],
    payload: bytes,
    verifier_key: bytes,
) -> dict[str, object]:
    """Return the nested snapshot from a rust-accepted authority record."""

    api = _snapshot_api()
    generation_floor = value.get("generation_floor")
    policy_digest = value.get("policy_digest")
    floor_mac = value.get("floor_mac")
    snapshot = value.get("snapshot")
    if (
        set(value) != {"schema", "generation_floor", "policy_digest", "snapshot", "floor_mac"}
        or _canonical_json_bytes_v3(value) != payload
        or isinstance(generation_floor, bool)
        or not isinstance(generation_floor, int)
        or not 1 <= generation_floor <= _MAX_GENERATION
        or not _valid_digest_v3(policy_digest)
        or not _valid_digest_v3(floor_mac)
        or not isinstance(snapshot, dict)
        or snapshot.get("generation") != generation_floor
        or snapshot.get("policy_digest") != policy_digest
        or not hmac.compare_digest(
            cast(str, floor_mac),
            _generation_floor_mac_v3(generation_floor, cast(str, policy_digest), verifier_key),
        )
    ):
        raise NativePolicySnapshotError("native_policy_snapshot_cache_invalid")
    api._validate_snapshot_v3(snapshot)
    integrity = snapshot.get("integrity")
    if not isinstance(integrity, Mapping) or not hmac.compare_digest(
        cast(str, integrity.get("mac")),
        api._snapshot_integrity_mac_v3(snapshot, verifier_key),
    ):
        raise NativePolicySnapshotError("native_policy_snapshot_cache_integrity_invalid")
    return cast(dict[str, object], snapshot)


def _read_v3_snapshot_file(
    path: Path,
    *,
    verifier_key: bytes | None = None,
) -> tuple[dict[str, object], bytes] | None:
    """Read one exact canonical snapshot from a private state file."""

    api = _snapshot_api()
    if os.name == "nt" and api._windows_path_has_reparse_component(path):
        raise NativePolicySnapshotError("native_policy_snapshot_cache_invalid")
    if os.name == "nt":
        payload = api._windows_read_snapshot_bytes(path)
        if payload is None:
            return None
    else:
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(path, flags)
        except FileNotFoundError:
            return None
        except OSError as error:
            raise NativePolicySnapshotError("native_policy_snapshot_cache_read_failed") from error
        try:
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_size <= 0
                or metadata.st_size > POLICY_SNAPSHOT_AUTHORITY_MAX_BYTES
                or (metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) & 0o077)
            ):
                raise NativePolicySnapshotError("native_policy_snapshot_cache_invalid")
            payload = bytearray()
            while len(payload) <= POLICY_SNAPSHOT_AUTHORITY_MAX_BYTES:
                chunk = os.read(
                    descriptor,
                    min(64 * 1024, POLICY_SNAPSHOT_AUTHORITY_MAX_BYTES + 1 - len(payload)),
                )
                if not chunk:
                    break
                payload.extend(chunk)
            if len(payload) != metadata.st_size or len(payload) > POLICY_SNAPSHOT_AUTHORITY_MAX_BYTES:
                raise NativePolicySnapshotError("native_policy_snapshot_cache_invalid")
        except OSError as error:
            raise NativePolicySnapshotError("native_policy_snapshot_cache_read_failed") from error
        finally:
            os.close(descriptor)
        payload = bytes(payload)
    value = api._strict_json_loads_v3(payload)
    if not isinstance(value, dict):
        raise NativePolicySnapshotError("native_policy_snapshot_cache_invalid")
    if value.get("schema") == POLICY_SNAPSHOT_AUTHORITY_SCHEMA:
        if verifier_key is None:
            raise NativePolicySnapshotError("native_policy_snapshot_cache_invalid")
        return _authority_snapshot_v3(value, payload, verifier_key), payload
    api._validate_snapshot_v3(value)
    canonical = api.snapshot_bytes_v3(value)
    if canonical != payload:
        raise NativePolicySnapshotError("native_policy_snapshot_cache_noncanonical")
    if verifier_key is not None:
        integrity = value.get("integrity")
        if not isinstance(integrity, Mapping) or not hmac.compare_digest(
            cast(str, integrity.get("mac")),
            api._snapshot_integrity_mac_v3(value, verifier_key),
        ):
            raise NativePolicySnapshotError("native_policy_snapshot_cache_integrity_invalid")
    return cast(dict[str, object], value), payload


def _read_v3_snapshot_cache(
    guard_home: Path,
    *,
    verifier_key: bytes | None = None,
) -> tuple[dict[str, object], bytes] | None:
    """Read the exact canonical snapshot retained across publisher restarts."""

    if os.name == "nt":
        api = _snapshot_api()
        with api._windows_private_state_binding(guard_home) as binding:
            return _read_v3_snapshot_file(
                binding.path / NATIVE_POLICY_SNAPSHOT_CACHE_NAME,
                verifier_key=verifier_key,
            )
    return _read_v3_snapshot_file(
        _snapshot_cache_path_v3(guard_home),
        verifier_key=verifier_key,
    )


def _write_v3_snapshot_file(
    guard_home: Path,
    name: str,
    snapshot: Mapping[str, object],
) -> bytes:
    """Atomically retain one signed snapshot in a private state file."""

    api = _snapshot_api()
    payload = snapshot_bytes_v3(snapshot)
    if os.name == "nt":
        temporary_name = f".{NATIVE_POLICY_SNAPSHOT_CACHE_NAME}.{secrets.token_hex(16)}.tmp"
        try:
            with api._windows_private_state_binding(guard_home) as binding:
                api._windows_write_private_file_atomic(
                    parent_path=binding.path,
                    parent_handle=binding.handle,
                    directory_handles=binding.handles,
                    temporary_name=temporary_name,
                    destination_name=name,
                    payload=payload,
                    maximum_bytes=POLICY_SNAPSHOT_MAX_BYTES,
                    kind="cache",
                )
        except (NativePolicySnapshotError, OSError) as error:
            raise NativePolicySnapshotError("native_policy_snapshot_cache_write_failed") from error
        return payload
    state_dir = _runtime_state_directory(guard_home)
    path = state_dir / name
    temporary = state_dir / f".{NATIVE_POLICY_SNAPSHOT_CACHE_NAME}.{secrets.token_hex(16)}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(temporary, flags, 0o600)
    except OSError as error:
        raise NativePolicySnapshotError("native_policy_snapshot_cache_write_failed") from error
    try:
        written = 0
        while written < len(payload):
            written += os.write(descriptor, payload[written:])
        os.fsync(descriptor)
    except OSError as error:
        raise NativePolicySnapshotError("native_policy_snapshot_cache_write_failed") from error
    finally:
        os.close(descriptor)
    try:
        os.replace(temporary, path)
        path.chmod(0o600)
        directory_descriptor = os.open(
            state_dir,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0),
        )
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    except OSError as error:
        raise NativePolicySnapshotError("native_policy_snapshot_cache_sync_failed") from error
    finally:
        with suppress(FileNotFoundError):
            temporary.unlink()
    return payload


def _write_v3_snapshot_cache(guard_home: Path, snapshot: Mapping[str, object]) -> bytes:
    """Atomically retain one signed snapshot before attempting resident IPC."""

    return _write_v3_snapshot_file(guard_home, NATIVE_POLICY_SNAPSHOT_CACHE_NAME, snapshot)


def _snapshot_pending_path_v3(guard_home: Path) -> Path:
    return _runtime_state_directory(guard_home) / _NATIVE_POLICY_SNAPSHOT_PENDING_NAME


def _clear_v3_snapshot_pending(guard_home: Path) -> None:
    if os.name == "nt":
        api = _snapshot_api()
        with api._windows_private_state_binding(guard_home) as binding:
            api._windows_delete_private_child(
                parent_path=binding.path,
                parent_handle=binding.handle,
                name=_NATIVE_POLICY_SNAPSHOT_PENDING_NAME,
            )
        return
    with suppress(FileNotFoundError):
        _snapshot_pending_path_v3(guard_home).unlink()


def _recover_v3_snapshot_transaction(guard_home: Path, verifier_key: bytes) -> None:
    """Complete a snapshot/cache transaction left by a process crash."""

    if os.name == "nt":
        api = _snapshot_api()
        with api._windows_private_state_binding(guard_home) as binding:
            pending = _read_v3_snapshot_file(
                binding.path / _NATIVE_POLICY_SNAPSHOT_PENDING_NAME,
                verifier_key=verifier_key,
            )
    else:
        pending_path = _snapshot_pending_path_v3(guard_home)
        pending = _read_v3_snapshot_file(pending_path, verifier_key=verifier_key)
    if pending is None:
        return
    pending_snapshot, pending_bytes = pending
    pending_generation = pending_snapshot.get("generation")
    pending_policy_digest = pending_snapshot.get("policy_digest")
    if not isinstance(pending_generation, int) or not _valid_digest_v3(pending_policy_digest):
        raise NativePolicySnapshotError("native_policy_snapshot_transaction_invalid")
    current = _read_v3_generation_state(guard_home)
    if current is not None and current[0] > pending_generation:
        # A newer generation is already committed. The pending candidate can
        # never be retried without violating monotonic ordering.
        _clear_v3_snapshot_pending(guard_home)
        return
    if current is not None and current[0] == pending_generation and current[1] != pending_policy_digest:
        raise NativePolicySnapshotError("native_policy_snapshot_transaction_conflict")
    cached = _read_v3_snapshot_cache(guard_home, verifier_key=verifier_key)
    if cached is not None and cached[1] != pending_bytes:
        cached_generation = cached[0].get("generation")
        if isinstance(cached_generation, int) and cached_generation > pending_generation:
            raise NativePolicySnapshotError("native_policy_snapshot_transaction_conflict")
        _write_v3_snapshot_cache(guard_home, pending_snapshot)
    elif cached is None:
        _write_v3_snapshot_cache(guard_home, pending_snapshot)
    if current is None or current[0] < pending_generation:
        _write_v3_generation_state(
            guard_home,
            generation=pending_generation,
            policy_digest=cast(str, pending_policy_digest),
        )
    _clear_v3_snapshot_pending(guard_home)


@contextmanager
def _v3_generation_lock(guard_home: Path, *, deadline_monotonic: float | None) -> Iterator[int]:
    with ExitStack() as resources:
        if os.name == "nt":
            api = _snapshot_api()
            binding = resources.enter_context(api._windows_private_directory_binding(guard_home))
            path = binding.path / _V3_GENERATION_LOCK_NAME
            try:
                lock_fd = api._windows_open_private_fd(path, maximum_bytes=_MAX_STATE_BYTES)
            except NativePolicySnapshotError as error:
                raise NativePolicySnapshotError("native_policy_snapshot_generation_lock_invalid") from error
        else:
            _private_guard_home(guard_home)
            path = guard_home / _V3_GENERATION_LOCK_NAME
            flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
            try:
                lock_fd = os.open(path, flags, 0o600)
            except OSError as error:
                raise NativePolicySnapshotError("native_policy_snapshot_generation_lock_invalid") from error
        try:
            metadata = os.fstat(lock_fd)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > _MAX_STATE_BYTES:
                raise NativePolicySnapshotError("native_policy_snapshot_generation_lock_invalid")
            if os.name != "nt" and (metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) & 0o077):
                raise NativePolicySnapshotError("native_policy_snapshot_generation_lock_invalid")
            if metadata.st_size == 0:
                os.write(lock_fd, b"0")
                os.fsync(lock_fd)
            deadline = deadline_monotonic if deadline_monotonic is not None else time.monotonic() + 1.0
            if os.name != "nt":
                import fcntl

                while True:
                    try:
                        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                        break
                    except BlockingIOError as error:
                        remaining = deadline - time.monotonic()
                        if remaining <= 0:
                            raise NativePolicySnapshotError("native_policy_snapshot_generation_lock_timeout") from error
                        time.sleep(min(0.01, remaining))
            else:
                import msvcrt

                while True:
                    try:
                        os.lseek(lock_fd, 0, os.SEEK_SET)
                        msvcrt.locking(lock_fd, msvcrt.LK_NBLCK, 1)
                        break
                    except OSError as error:
                        remaining = deadline - time.monotonic()
                        if remaining <= 0:
                            raise NativePolicySnapshotError("native_policy_snapshot_generation_lock_timeout") from error
                        time.sleep(min(0.01, remaining))
            try:
                yield lock_fd
            finally:
                if os.name != "nt":
                    import fcntl

                    fcntl.flock(lock_fd, fcntl.LOCK_UN)
                else:
                    import msvcrt

                    os.lseek(lock_fd, 0, os.SEEK_SET)
                    msvcrt.locking(lock_fd, msvcrt.LK_UNLCK, 1)
        finally:
            os.close(lock_fd)


def _read_v3_generation_state(guard_home: Path) -> tuple[int, str] | None:
    path = guard_home / _V3_GENERATION_STATE_NAME
    if os.name == "nt":
        api = _snapshot_api()
        with api._windows_private_state_binding(guard_home) as binding:
            payload = _windows_read_generation_state_bytes(binding.path.parent / _V3_GENERATION_STATE_NAME)
        if payload is None:
            return None
    else:
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(path, flags)
        except FileNotFoundError:
            return None
        except OSError as error:
            raise NativePolicySnapshotError("native_policy_snapshot_generation_state_invalid") from error
        try:
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_size <= 0
                or metadata.st_size > _MAX_STATE_BYTES
                or (metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) & 0o077)
            ):
                raise NativePolicySnapshotError("native_policy_snapshot_generation_state_invalid")
            payload = os.read(descriptor, _MAX_STATE_BYTES + 1)
        finally:
            os.close(descriptor)
    value = _strict_json_loads_v3(payload)
    if not isinstance(value, dict) or set(value) != {"schema", "generation", "policy_digest"}:
        raise NativePolicySnapshotError("native_policy_snapshot_generation_state_invalid")
    generation = value.get("generation")
    policy_digest = value.get("policy_digest")
    if (
        value.get("schema") != _V3_GENERATION_SCHEMA
        or isinstance(generation, bool)
        or not isinstance(generation, int)
        or not 1 <= generation <= _MAX_GENERATION
        or not _valid_digest_v3(policy_digest)
        or _canonical_json_bytes_v3(value) != payload
    ):
        raise NativePolicySnapshotError("native_policy_snapshot_generation_state_invalid")
    return generation, cast(str, policy_digest)


def _write_v3_generation_state(guard_home: Path, *, generation: int, policy_digest: str) -> None:
    api = _snapshot_api()
    value = {"generation": generation, "policy_digest": policy_digest, "schema": _V3_GENERATION_SCHEMA}
    payload = _canonical_json_bytes_v3(value)
    if os.name == "nt":
        temporary_name = f".{_V3_GENERATION_STATE_NAME}.{secrets.token_hex(16)}.tmp"
        try:
            with api._windows_private_directory_binding(guard_home) as binding:
                api._windows_write_private_file_atomic(
                    parent_path=binding.path,
                    parent_handle=binding.handle,
                    directory_handles=binding.handles,
                    temporary_name=temporary_name,
                    destination_name=_V3_GENERATION_STATE_NAME,
                    payload=payload,
                    maximum_bytes=_MAX_STATE_BYTES,
                    kind="generation_state",
                )
        except (NativePolicySnapshotError, OSError) as error:
            raise NativePolicySnapshotError("native_policy_snapshot_generation_state_write_failed") from error
        return
    path = guard_home / _V3_GENERATION_STATE_NAME
    temporary = guard_home / f".{_V3_GENERATION_STATE_NAME}.{secrets.token_hex(16)}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(temporary, flags, 0o600)
    except OSError as error:
        raise NativePolicySnapshotError("native_policy_snapshot_generation_state_write_failed") from error
    try:
        os.write(descriptor, payload)
        os.fsync(descriptor)
    except OSError as error:
        raise NativePolicySnapshotError("native_policy_snapshot_generation_state_write_failed") from error
    finally:
        os.close(descriptor)
    try:
        os.replace(temporary, path)
        path.chmod(0o600)
        directory_descriptor = os.open(
            guard_home,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0),
        )
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    except OSError as error:
        raise NativePolicySnapshotError("native_policy_snapshot_generation_state_write_failed") from error
    finally:
        with suppress(FileNotFoundError):
            temporary.unlink()
