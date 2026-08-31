"""Generation-bound native policy snapshots for PostToolUse envelopes."""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import stat
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from pathlib import Path

_STATE_SCHEMA = "hol-guard-native-policy-generation.v1"
_STATE_NAME = "native-policy-generation.json"
_LOCK_NAME = "native-policy-generation.lock"
_MAX_STATE_BYTES = 4 * 1024
_MAX_GENERATION = (1 << 64) - 1


class NativePolicySnapshotError(RuntimeError):
    """Raised when the durable native-policy generation cannot be trusted."""


def _policy_digest(*, config_digest: str, rule_digest: str) -> str:
    policy_bytes = json.dumps(
        {"config_digest": config_digest, "rule_digest": rule_digest},
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(policy_bytes).hexdigest()


def _private_guard_home(guard_home: Path) -> None:
    try:
        metadata = guard_home.lstat()
    except FileNotFoundError:
        guard_home.mkdir(mode=0o700, parents=True, exist_ok=True)
        metadata = guard_home.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise NativePolicySnapshotError("native_policy_generation_home_invalid")
    if os.name != "nt" and (metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) & 0o077):
        raise NativePolicySnapshotError("native_policy_generation_home_invalid")


@contextmanager
def _generation_lock(guard_home: Path) -> Iterator[None]:
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
        if os.name == "nt":
            import msvcrt

            if metadata.st_size == 0:
                os.write(descriptor, b"0")
            os.lseek(descriptor, 0, os.SEEK_SET)
            msvcrt.locking(descriptor, msvcrt.LK_LOCK, 1)
        else:
            import fcntl

            fcntl.flock(descriptor, fcntl.LOCK_EX)
        try:
            yield
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
        if os.name != "nt":
            directory_descriptor = os.open(guard_home, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(directory_descriptor)
            finally:
                os.close(directory_descriptor)
    finally:
        with suppress(FileNotFoundError):
            temporary.unlink()


def _generation_for_policy(guard_home: Path, policy_digest: str) -> int:
    with _generation_lock(guard_home):
        current = _read_generation_state(guard_home)
        if current is None:
            generation = 1
        elif current[1] == policy_digest:
            return current[0]
        elif current[0] == _MAX_GENERATION:
            raise NativePolicySnapshotError("native_policy_generation_exhausted")
        else:
            generation = current[0] + 1
        _write_generation_state(guard_home, generation=generation, policy_digest=policy_digest)
        return generation


def native_policy_snapshot(
    *,
    guard_home: Path,
    rule_digest: str,
    observe_mode: bool,
) -> dict[str, object]:
    mode = "observe" if observe_mode else "enforce"
    config_bytes = json.dumps({"mode": mode}, separators=(",", ":"), sort_keys=True).encode("utf-8")
    config_digest = hashlib.sha256(config_bytes).hexdigest()
    policy_digest = _policy_digest(config_digest=config_digest, rule_digest=rule_digest)
    generation = _generation_for_policy(guard_home, policy_digest)
    return {
        "schema": "hol-guard-native-policy.v1",
        "generation": generation,
        "policy_digest": policy_digest,
        "config_digest": config_digest,
        "rule_digest": rule_digest,
        "mode": mode,
    }


__all__ = ["NativePolicySnapshotError", "native_policy_snapshot"]
