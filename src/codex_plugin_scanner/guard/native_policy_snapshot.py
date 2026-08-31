"""Generation-bound native policy snapshots for PostToolUse envelopes."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import threading
import time
from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path
from typing import BinaryIO, cast

_STATE_SCHEMA = "hol-guard-native-policy-generation.v1"
_MAX_STATE_BYTES = 4 * 1024
_LOCK_TIMEOUT_SECONDS = 0.1
_GENERATION_LOCK = threading.Lock()
_current_policy_digest = ""
_current_generation = 0
_shared_generation_cache: dict[Path, tuple[str, int, tuple[int, int, int, int]]] = {}


class NativePolicyGenerationError(RuntimeError):
    """Raised when the shared policy generation cannot be advanced safely."""


def _process_local_generation(policy_digest: str) -> int:
    global _current_generation, _current_policy_digest
    if policy_digest == _current_policy_digest and _current_generation > 0:
        return _current_generation
    wall_clock_generation = max(1, time.time_ns() // 1_000)
    _current_generation = max(wall_clock_generation, _current_generation + 1)
    _current_policy_digest = policy_digest
    return _current_generation


def _lock_file(handle: BinaryIO) -> None:
    if os.name == "nt":
        import msvcrt

        _ = handle.seek(0)
        if not handle.read(1):
            _ = handle.write(b"0")
            handle.flush()
        _ = handle.seek(0)
        msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
        return
    import fcntl

    _ = fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)


def _unlock_file(handle: BinaryIO) -> None:
    if os.name == "nt":
        import msvcrt

        _ = handle.seek(0)
        msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
        return
    import fcntl

    _ = fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


@contextmanager
def _generation_file_lock(guard_home: Path) -> Generator[None, None, None]:
    guard_home.mkdir(parents=True, exist_ok=True)
    lock_path = guard_home / "native-policy-generation.lock"
    if lock_path.is_symlink() or (lock_path.exists() and not lock_path.is_file()):
        raise NativePolicyGenerationError("native_policy_generation_lock_invalid")
    flags = os.O_RDWR | os.O_CREAT
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(lock_path, flags, 0o600)
    with os.fdopen(descriptor, "r+b", closefd=True) as handle:
        deadline = time.monotonic() + _LOCK_TIMEOUT_SECONDS
        while True:
            try:
                _lock_file(handle)
                break
            except OSError as exc:
                if time.monotonic() >= deadline:
                    raise NativePolicyGenerationError("native_policy_generation_lock_busy") from exc
                time.sleep(0.002)
        try:
            yield
        finally:
            _unlock_file(handle)


def _read_generation_state(path: Path) -> tuple[str, int] | None:
    if not path.exists():
        return None
    if path.is_symlink() or not path.is_file() or path.stat().st_size > _MAX_STATE_BYTES:
        raise NativePolicyGenerationError("native_policy_generation_state_invalid")
    try:
        payload = cast(object, json.loads(path.read_bytes()))
    except (OSError, json.JSONDecodeError) as exc:
        raise NativePolicyGenerationError("native_policy_generation_state_invalid") from exc
    if not isinstance(payload, dict) or set(payload) != {"schema", "policy_digest", "generation"}:
        raise NativePolicyGenerationError("native_policy_generation_state_invalid")
    typed_payload = cast(dict[str, object], payload)
    policy_digest = typed_payload.get("policy_digest")
    generation = typed_payload.get("generation")
    if (
        typed_payload.get("schema") != _STATE_SCHEMA
        or not isinstance(policy_digest, str)
        or len(policy_digest) != 64
        or not isinstance(generation, int)
        or isinstance(generation, bool)
        or generation <= 0
    ):
        raise NativePolicyGenerationError("native_policy_generation_state_invalid")
    return policy_digest, generation


def _write_generation_state(path: Path, policy_digest: str, generation: int) -> None:
    encoded = json.dumps(
        {"schema": _STATE_SCHEMA, "policy_digest": policy_digest, "generation": generation},
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    descriptor, temporary_name = tempfile.mkstemp(prefix=".native-policy-generation.", dir=path.parent)
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            if hasattr(os, "fchmod"):
                os.fchmod(handle.fileno(), 0o600)
            _ = handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, path)
        os.chmod(path, 0o600)
    finally:
        temporary_path.unlink(missing_ok=True)


def _state_identity(path: Path) -> tuple[int, int, int, int]:
    metadata = path.lstat()
    if path.is_symlink() or not path.is_file() or metadata.st_size > _MAX_STATE_BYTES:
        raise NativePolicyGenerationError("native_policy_generation_state_invalid")
    return metadata.st_dev, metadata.st_ino, metadata.st_mtime_ns, metadata.st_size


def _shared_generation(guard_home: Path, policy_digest: str) -> int:
    cache_key = guard_home.absolute()
    state_path = guard_home / "native-policy-generation.json"
    try:
        cached = _shared_generation_cache.get(cache_key)
        if cached is not None and cached[0] == policy_digest and _state_identity(state_path) == cached[2]:
            return cached[1]
        with _generation_file_lock(guard_home):
            previous = _read_generation_state(state_path)
            if previous is not None and previous[0] == policy_digest:
                generation = previous[1]
            else:
                previous_generation = previous[1] if previous is not None else 0
                generation = max(1, time.time_ns() // 1_000, previous_generation + 1)
                _write_generation_state(state_path, policy_digest, generation)
            _shared_generation_cache[cache_key] = (
                policy_digest,
                generation,
                _state_identity(state_path),
            )
            return generation
    except NativePolicyGenerationError:
        raise
    except OSError as exc:
        raise NativePolicyGenerationError("native_policy_generation_io_failed") from exc


def native_policy_snapshot(
    *, rule_digest: str, observe_mode: bool, guard_home: Path | None = None
) -> dict[str, object]:
    mode = "observe" if observe_mode else "enforce"
    config_bytes = json.dumps({"mode": mode}, separators=(",", ":"), sort_keys=True).encode("utf-8")
    config_digest = hashlib.sha256(config_bytes).hexdigest()
    policy_bytes = json.dumps(
        {"config_digest": config_digest, "rule_digest": rule_digest},
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    policy_digest = hashlib.sha256(policy_bytes).hexdigest()
    with _GENERATION_LOCK:
        generation = (
            _process_local_generation(policy_digest)
            if guard_home is None
            else _shared_generation(guard_home, policy_digest)
        )
    return {
        "schema": "hol-guard-native-policy.v1",
        "generation": generation,
        "policy_digest": policy_digest,
        "config_digest": config_digest,
        "rule_digest": rule_digest,
        "mode": mode,
    }


__all__ = ["NativePolicyGenerationError", "native_policy_snapshot"]
