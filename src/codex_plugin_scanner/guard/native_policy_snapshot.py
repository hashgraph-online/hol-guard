"""Compatibility façade for generation-bound native policy snapshots.

The public import path remains stable while protocol, storage, platform, and
publisher implementations live in bounded modules.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import stat
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from pathlib import Path
from typing import TYPE_CHECKING

from . import native_policy_snapshot_codec as _codec
from . import native_policy_snapshot_constants as _constants
from . import native_policy_snapshot_contract as _contract
from . import native_policy_snapshot_generation as _generation
from . import native_policy_snapshot_policy as _policy
from . import native_policy_snapshot_storage as _storage
from . import native_policy_snapshot_windows_acl as _windows_acl
from . import native_policy_snapshot_windows_io as _windows_io
from . import native_policy_snapshot_windows_key as _windows_key
from . import native_policy_snapshot_windows_state as _windows_state
from . import native_policy_snapshot_windows_support as _windows_support
from .native_policy_snapshot_publisher import NativePolicySnapshotPublisher

globals().update({name: getattr(_constants, name) for name in _constants.__all__})
NATIVE_POLICY_SNAPSHOT_CACHE_NAME = _constants.NATIVE_POLICY_SNAPSHOT_CACHE_NAME
NativePolicySnapshotError = _constants.NativePolicySnapshotError
POLICY_SNAPSHOT_ACK_REQUIRES_NEW_GENERATION = _constants.POLICY_SNAPSHOT_ACK_REQUIRES_NEW_GENERATION
POLICY_SNAPSHOT_INTEGRITY_DOMAIN = _constants.POLICY_SNAPSHOT_INTEGRITY_DOMAIN
POLICY_SNAPSHOT_PUSH_SCHEMA = _constants.POLICY_SNAPSHOT_PUSH_SCHEMA
POLICY_SNAPSHOT_SCHEMA = _constants.POLICY_SNAPSHOT_SCHEMA
POLICY_SNAPSHOT_V3_SCHEMA = _constants.POLICY_SNAPSHOT_V3_SCHEMA
_LOCK_NAME = _constants._LOCK_NAME
_MAX_GENERATION = _constants._MAX_GENERATION
_MAX_STATE_BYTES = _constants._MAX_STATE_BYTES
_STATE_NAME = _constants._STATE_NAME
_STATE_SCHEMA = _constants._STATE_SCHEMA
_WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT = _constants._WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT
derive_native_policy_verifier_key = _codec.derive_native_policy_verifier_key
native_policy_verifier_key_id = _codec.native_policy_verifier_key_id
build_policy_snapshot_v3 = _contract.build_policy_snapshot_v3
snapshot_bytes_v3 = _contract.snapshot_bytes_v3
snapshot_config_digest_v3 = _contract.snapshot_config_digest_v3
snapshot_signing_bytes_v3 = _contract.snapshot_signing_bytes_v3
native_policy_snapshot_v3 = _generation.native_policy_snapshot_v3
effective_native_policy_v3 = _contract.effective_native_policy_v3
provision_native_policy_verifier_key = _windows_key.provision_native_policy_verifier_key

_snapshot_integrity_mac_v3 = _contract._snapshot_integrity_mac_v3
_snapshot_policy_digest_v3 = _contract._snapshot_policy_digest_v3
_validate_snapshot_v3 = _contract._validate_snapshot_v3
_strict_json_loads_v3 = _codec._strict_json_loads_v3
_clear_v3_snapshot_pending = _storage._clear_v3_snapshot_pending
_read_v3_generation_state = _storage._read_v3_generation_state
_read_v3_snapshot_cache = _storage._read_v3_snapshot_cache
_read_v3_snapshot_file = _storage._read_v3_snapshot_file
_recover_v3_snapshot_transaction = _storage._recover_v3_snapshot_transaction
_v3_generation_lock = _storage._v3_generation_lock
_windows_read_snapshot_bytes = _storage._windows_read_snapshot_bytes
_write_v3_generation_state = _storage._write_v3_generation_state
_write_v3_snapshot_cache = _storage._write_v3_snapshot_cache
_write_v3_snapshot_file = _storage._write_v3_snapshot_file
_windows_dll = _windows_support._windows_dll
_windows_file_information_type = _windows_support._windows_file_information_type
_windows_owner_sid = _windows_support._windows_owner_sid
_windows_security_attributes_type = _windows_support._windows_security_attributes_type
_windows_private_descriptor = _windows_support._windows_private_descriptor
_windows_path_has_reparse_component = _windows_support._windows_path_has_reparse_component
_windows_close_handle = _windows_io._windows_close_handle
_windows_open_handle = _windows_io._windows_open_handle
_windows_apply_private_dacl = _windows_io._windows_apply_private_dacl
_windows_verify_private_dacl = _windows_acl._windows_verify_private_dacl
_windows_ensure_private_directory = _windows_state._windows_ensure_private_directory
_v3_generation_for_policy = _generation._v3_generation_for_policy
_merge_effective_native_policies = _policy._merge_effective_native_policies
_normalize_scope_text_v3 = _policy._normalize_scope_text_v3
_utf8_size_v3 = _codec._utf8_size_v3
_valid_bounded_string_v3 = _codec._valid_bounded_string_v3
_valid_selector_key_v3 = _codec._valid_selector_key_v3
_normalized_harness_selector_v3 = _codec._normalized_harness_selector_v3
_validate_json_limits_v3 = _codec._validate_json_limits_v3
_canonical_json_bytes_v3 = _codec._canonical_json_bytes_v3
_digest_v3 = _codec._digest_v3
_runtime_state_directory = _windows_support._runtime_state_directory
_windows_read_key = _windows_key._windows_read_key
_windows_provision_verifier_key = _windows_key._windows_provision_verifier_key
_scope_digest_v3 = _policy._scope_digest_v3
_config_value = _policy._config_value
_action_value = _policy._action_value
_string_map = _policy._string_map
_harness_risk_map = _policy._harness_risk_map
_harness_action_map = _policy._harness_action_map
_require_snapshot_mapping_fields_v3 = _contract._require_snapshot_mapping_fields_v3
_valid_u16_v3 = _contract._valid_u16_v3
_valid_u64_v3 = _contract._valid_u64_v3
_valid_digest_v3 = _contract._valid_digest_v3
_policy_snapshot_push_bytes_v3 = _contract._policy_snapshot_push_bytes_v3
_snapshot_cache_path_v3 = _storage._snapshot_cache_path_v3
_snapshot_pending_path_v3 = _storage._snapshot_pending_path_v3
_snapshot_inputs_v3 = _generation._snapshot_inputs_v3
_snapshot_matches_inputs_v3 = _generation._snapshot_matches_inputs_v3
_stricter_action = _policy._stricter_action

if TYPE_CHECKING:
    from .store import GuardStore


def _policy_digest(*, config_digest: str, rule_digest: str) -> str:
    policy_bytes = json.dumps(
        {"config_digest": config_digest, "rule_digest": rule_digest},
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(policy_bytes).hexdigest()


def _private_guard_home(guard_home: Path) -> None:
    if os.name == "nt" and _windows_path_has_reparse_component(guard_home):
        raise NativePolicySnapshotError("native_policy_generation_home_invalid")
    try:
        metadata = guard_home.lstat()
    except FileNotFoundError:
        guard_home.mkdir(mode=0o700, parents=True, exist_ok=True)
        metadata = guard_home.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise NativePolicySnapshotError("native_policy_generation_home_invalid")
    if os.name != "nt" and (metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) & 0o022):
        raise NativePolicySnapshotError("native_policy_generation_home_invalid")


def _acquire_generation_lock(descriptor: int, *, deadline_monotonic: float | None) -> None:
    if os.name != "nt":
        import fcntl

        deadline = deadline_monotonic if deadline_monotonic is not None else time.monotonic() + 1.0
        while True:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return
            except BlockingIOError as error:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise NativePolicySnapshotError("native_policy_generation_lock_timeout") from error
                time.sleep(min(0.01, remaining))

    import msvcrt

    deadline = deadline_monotonic if deadline_monotonic is not None else time.monotonic() + 1.0
    while True:
        try:
            os.lseek(descriptor, 0, os.SEEK_SET)
            msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
            return
        except OSError as error:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise NativePolicySnapshotError("native_policy_generation_lock_timeout") from error
            time.sleep(min(0.01, remaining))


@contextmanager
def _generation_lock(guard_home: Path, *, deadline_monotonic: float | None) -> Iterator[int]:
    _private_guard_home(guard_home)
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(guard_home / _LOCK_NAME, flags, 0o600)
    except OSError as error:
        raise NativePolicySnapshotError("native_policy_generation_lock_invalid") from error
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or (
            os.name != "nt" and (metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) & 0o077)
        ):
            raise NativePolicySnapshotError("native_policy_generation_lock_invalid")
        if metadata.st_size == 0:
            os.write(descriptor, b"0")
            os.fsync(descriptor)
        _acquire_generation_lock(descriptor, deadline_monotonic=deadline_monotonic)
        try:
            yield descriptor
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


def _read_generation_state(guard_home: Path) -> tuple[int, str] | None:
    path = guard_home / _STATE_NAME
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except FileNotFoundError:
        return None
    except OSError as error:
        raise NativePolicySnapshotError("native_policy_generation_state_invalid") from error
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_size > _MAX_STATE_BYTES
            or (os.name != "nt" and (metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) & 0o077))
        ):
            raise NativePolicySnapshotError("native_policy_generation_state_invalid")
        payload = os.read(descriptor, _MAX_STATE_BYTES + 1)
    finally:
        os.close(descriptor)
    try:
        state = json.loads(payload)
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise NativePolicySnapshotError("native_policy_generation_state_invalid") from error
    if not isinstance(state, dict):
        raise NativePolicySnapshotError("native_policy_generation_state_invalid")
    generation = state.get("generation")
    policy_digest = state.get("policy_digest")
    if (
        state.get("schema") != _STATE_SCHEMA
        or type(generation) is not int
        or not 1 <= generation <= _MAX_GENERATION
        or not isinstance(policy_digest, str)
        or len(policy_digest) != 64
        or any(character not in "0123456789abcdef" for character in policy_digest)
    ):
        raise NativePolicySnapshotError("native_policy_generation_state_invalid")
    return generation, policy_digest


def _write_generation_state(guard_home: Path, *, generation: int, policy_digest: str) -> None:
    path = guard_home / _STATE_NAME
    payload = json.dumps(
        {"generation": generation, "policy_digest": policy_digest, "schema": _STATE_SCHEMA},
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    temporary = guard_home / f".{_STATE_NAME}.{secrets.token_hex(16)}.tmp"
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o600)
        committed_descriptor = os.open(
            path,
            os.O_RDWR | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            os.fsync(committed_descriptor)
        finally:
            os.close(committed_descriptor)
        if os.name != "nt":
            directory_descriptor = os.open(guard_home, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(directory_descriptor)
            finally:
                os.close(directory_descriptor)
    finally:
        with suppress(FileNotFoundError):
            temporary.unlink()


def _initialized_generation_for_policy(guard_home: Path, policy_digest: str) -> int | None:
    _private_guard_home(guard_home)
    lock_path = guard_home / _LOCK_NAME
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(lock_path, flags)
    except (FileNotFoundError, OSError):
        return None
    try:
        if os.read(descriptor, 1) != b"1":
            return None
    finally:
        os.close(descriptor)
    current = _read_generation_state(guard_home)
    if current is not None and current[1] == policy_digest:
        return current[0]
    return None


def _generation_for_policy(
    guard_home: Path,
    policy_digest: str,
    *,
    deadline_monotonic: float | None,
) -> int:
    initialized_generation = _initialized_generation_for_policy(guard_home, policy_digest)
    if initialized_generation is not None:
        return initialized_generation
    with _generation_lock(guard_home, deadline_monotonic=deadline_monotonic) as lock_descriptor:
        current = _read_generation_state(guard_home)
        if current is None:
            os.lseek(lock_descriptor, 0, os.SEEK_SET)
            if os.read(lock_descriptor, 1) == b"1":
                raise NativePolicySnapshotError("native_policy_generation_state_missing")
            generation = 1
        elif current[1] == policy_digest:
            os.lseek(lock_descriptor, 0, os.SEEK_SET)
            if os.read(lock_descriptor, 1) != b"1":
                os.lseek(lock_descriptor, 0, os.SEEK_SET)
                os.write(lock_descriptor, b"1")
                os.fsync(lock_descriptor)
            return current[0]
        elif current[0] == _MAX_GENERATION:
            raise NativePolicySnapshotError("native_policy_generation_exhausted")
        else:
            generation = current[0] + 1
        _write_generation_state(guard_home, generation=generation, policy_digest=policy_digest)
        os.lseek(lock_descriptor, 0, os.SEEK_SET)
        os.write(lock_descriptor, b"1")
        os.fsync(lock_descriptor)
        return generation


def native_policy_snapshot(
    *,
    guard_home: Path,
    rule_digest: str,
    observe_mode: bool,
    deadline_monotonic: float | None = None,
) -> dict[str, object]:
    mode = "observe" if observe_mode else "enforce"
    config_bytes = json.dumps({"mode": mode}, separators=(",", ":"), sort_keys=True).encode("utf-8")
    config_digest = hashlib.sha256(config_bytes).hexdigest()
    policy_digest = _policy_digest(config_digest=config_digest, rule_digest=rule_digest)
    generation = _generation_for_policy(
        guard_home,
        policy_digest,
        deadline_monotonic=deadline_monotonic,
    )
    return {
        "schema": "hol-guard-native-policy.v1",
        "generation": generation,
        "policy_digest": policy_digest,
        "config_digest": config_digest,
        "rule_digest": rule_digest,
        "mode": mode,
    }


_PUBLISHER_LOCK = threading.RLock()
_PUBLISHERS: dict[str, set[NativePolicySnapshotPublisher]] = {}


def _publisher_key(guard_home: Path) -> str:
    try:
        return str(guard_home.expanduser().resolve(strict=False))
    except (OSError, RuntimeError, ValueError):
        return str(guard_home)


def notify_native_policy_mutation(guard_home: Path) -> None:
    """Invalidate publishers for a control-plane policy/config mutation."""

    with _PUBLISHER_LOCK:
        publishers = tuple(_PUBLISHERS.get(_publisher_key(guard_home), ()))
    for publisher in publishers:
        publisher.request_publish()


def get_native_policy_snapshot_publisher(store: GuardStore) -> NativePolicySnapshotPublisher:
    """Return the per-Guard-home publisher shared by daemon hook workers."""

    key = _publisher_key(Path(store.guard_home))
    with _PUBLISHER_LOCK:
        for publisher in _PUBLISHERS.get(key, ()):
            if not publisher.closed:
                return publisher
        publisher = NativePolicySnapshotPublisher(store=store)
        _PUBLISHERS.setdefault(key, set()).add(publisher)
        return publisher


__all__ = [
    "NATIVE_POLICY_SNAPSHOT_CACHE_NAME",
    "POLICY_SNAPSHOT_ACK_REQUIRES_NEW_GENERATION",
    "POLICY_SNAPSHOT_INTEGRITY_DOMAIN",
    "POLICY_SNAPSHOT_PUSH_SCHEMA",
    "POLICY_SNAPSHOT_SCHEMA",
    "POLICY_SNAPSHOT_V3_SCHEMA",
    "NativePolicySnapshotError",
    "NativePolicySnapshotPublisher",
    "build_policy_snapshot_v3",
    "derive_native_policy_verifier_key",
    "effective_native_policy_v3",
    "get_native_policy_snapshot_publisher",
    "native_policy_snapshot",
    "native_policy_snapshot_v3",
    "native_policy_verifier_key_id",
    "notify_native_policy_mutation",
    "provision_native_policy_verifier_key",
    "snapshot_bytes_v3",
    "snapshot_config_digest_v3",
    "snapshot_signing_bytes_v3",
]
