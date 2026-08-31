"""Generation-bound native policy snapshots for PostToolUse envelopes."""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import re
import secrets
import stat
import threading
import time
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager, suppress
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

if TYPE_CHECKING:
    from .config import GuardConfig
    from .store import GuardStore

_STATE_SCHEMA = "hol-guard-native-policy-generation.v1"
_STATE_NAME = "native-policy-generation.json"
_LOCK_NAME = "native-policy-generation.lock"
_MAX_STATE_BYTES = 4 * 1024
_MAX_GENERATION = (1 << 64) - 1

# v3 is the only snapshot contract accepted by the managed Rust resident. The
# v1 helpers below remain intentionally isolated for explicit differential
# tests; production native hooks never call them.
POLICY_SNAPSHOT_V3_SCHEMA = "hol-guard-native-policy.v3"
# Compatibility alias for callers that used the schema name while the v3
# implementation was being introduced. It intentionally points only at v3.
POLICY_SNAPSHOT_SCHEMA = POLICY_SNAPSHOT_V3_SCHEMA
POLICY_SNAPSHOT_PUSH_SCHEMA = "guard-policy-snapshot-push.v1"
POLICY_SNAPSHOT_ACK_REQUIRES_NEW_GENERATION = "native_policy_snapshot_requires_new_generation"
POLICY_SNAPSHOT_V3_VERSION = 3
POLICY_SNAPSHOT_PROTOCOL_VERSION = 1
POLICY_SNAPSHOT_MAX_BYTES = 256 * 1024
POLICY_SNAPSHOT_MAX_STRING_BYTES = 4 * 1024
POLICY_SNAPSHOT_MAX_MAP_ENTRIES = 256
POLICY_SNAPSHOT_MAX_HARNESS_ENTRIES = 64
POLICY_SNAPSHOT_MAX_JSON_DEPTH = 32
POLICY_SNAPSHOT_MAX_JSON_COLLECTION_ITEMS = 4_096
POLICY_SNAPSHOT_MAX_JSON_STRING_BYTES = 1024 * 1024
POLICY_SNAPSHOT_MAX_EXPIRY_MS = 24 * 60 * 60 * 1000
POLICY_SNAPSHOT_INTEGRITY_ALGORITHM = "hmac-sha256"

# Keep these bytes byte-for-byte aligned with guard-policy-snapshot. Rust's
# HMAC helper authenticates ``domain || message`` rather than using a second
# HMAC field, so the Python functions below do the same concatenation.
POLICY_SNAPSHOT_INTEGRITY_DOMAIN = b"hol-guard-native-policy-snapshot-v3\0"
POLICY_SNAPSHOT_VERIFIER_DERIVATION_DOMAIN = b"hol-guard-native-policy-verifier-v1\0"

NATIVE_RUNTIME_STATE_DIRECTORY = "native-runtime"
NATIVE_POLICY_VERIFIER_KEY_NAME = "policy-verifier.key"
_V3_GENERATION_SCHEMA = "guard-native-policy-snapshot-generation.v3"
_V3_GENERATION_STATE_NAME = "native-policy-snapshot-generation-v3.json"
_V3_GENERATION_LOCK_NAME = "native-policy-snapshot-generation-v3.lock"
_RUST_GENERATION_FLOOR_NAME = "policy-snapshot-generation-floor.json"
_RUST_SNAPSHOT_STATE_NAME = "policy-snapshot-v3.json"
NATIVE_POLICY_SNAPSHOT_CACHE_NAME = "policy-snapshot-publisher-v3.json"
_NATIVE_POLICY_SNAPSHOT_PENDING_NAME = "policy-snapshot-publisher-v3.pending.json"
_VERIFIER_KEY_BYTES = 32
_PUBLISH_RETRY_SECONDS = 0.25
_PUBLISH_TIMEOUT_SECONDS = 2.0
_MAX_ACK_BYTES = 4 * 1024
_RENEWAL_LEAD_SECONDS = 5 * 60
_RENEWAL_JITTER_MAX_SECONDS = 30.0
_PUBLISH_RETRY_MAX_SECONDS = 5.0
_REQUIRED_PUBLISH_FEATURES = frozenset(
    {
        "policy-snapshot-v3",
        "policy-snapshot-push-v1",
        "native-policy-in-memory-v1",
        "native-resident-client-v1",
    }
)
_VALID_ACTIONS = frozenset({"allow", "warn", "review", "require-reapproval", "sandbox-required", "block"})
_VALID_POSTURES = frozenset({"protected", "extra_careful", "watch"})
_VALID_SECURITY_LEVELS = frozenset({"relaxed", "gentle", "balanced", "strict", "paranoid", "custom"})
_VALID_SANDBOX_ANALYSIS = frozenset({"off", "suspicious", "strict"})
_VALID_REDACTION_LEVELS = frozenset({"full", "partial", "none"})
_VALID_RISK_ACTION_KEYS = frozenset(
    {
        "local_secret_read",
        "credential_exfiltration",
        "data_flow_exfiltration",
        "destructive_shell",
        "encoded_execution",
        "network_egress",
        "prompt_injection",
        "mcp_dangerous_tool",
        "malicious_skill",
        "package_script",
        "persistence",
        "guard_bypass",
        "cloud_advisory",
        "encoded_exfiltration",
        "execution",
        "supply_chain",
        "policy_bypass",
    }
)
_SNAPSHOT_FIELDS = frozenset(
    {
        "schema",
        "version",
        "generation",
        "policy_digest",
        "config_digest",
        "rule_digest",
        "runtime_identity",
        "protocol_version",
        "mode",
        "scope_contract",
        "effective_policy",
        "issued_at_ms",
        "expires_at_ms",
        "integrity",
    }
)
_SCOPE_FIELDS = frozenset({"schema", "kind", "scope_digest", "workspace_binding"})
_EFFECTIVE_POLICY_FIELDS = frozenset(
    {
        "protection_posture",
        "security_level",
        "default_action",
        "unknown_publisher_action",
        "changed_hash_action",
        "new_network_domain_action",
        "subprocess_action",
        "risk_actions",
        "harness_risk_actions",
        "harness_actions",
        "publisher_actions",
        "artifact_actions",
        "sandbox_analysis",
        "receipt_redaction_level",
    }
)
_INTEGRITY_FIELDS = frozenset({"algorithm", "key_id", "mac"})
_PUSH_ENVELOPE_FIELDS = frozenset({"operation", "deadline_budget_ms", "request"})
_PUSH_REQUEST_FIELDS = frozenset({"schema", "snapshot"})
_VALID_INPUT_MODES = frozenset({"observe", "prompt", "enforce"})
_MAX_U16 = (1 << 16) - 1
_MAX_U64 = (1 << 64) - 1

# Windows verifier state uses the same protected explicit owner+SYSTEM DACL
# contract as the Rust resident-state helper.  These constants are kept local
# to avoid making ctypes part of the normal POSIX import path's API.
_WINDOWS_GENERIC_READ = 0x80000000
_WINDOWS_GENERIC_WRITE = 0x40000000
_WINDOWS_FILE_SHARE_READ = 0x00000001
_WINDOWS_FILE_SHARE_WRITE = 0x00000002
_WINDOWS_CREATE_NEW = 1
_WINDOWS_OPEN_EXISTING = 3
_WINDOWS_FILE_ATTRIBUTE_NORMAL = 0x00000080
_WINDOWS_FILE_ATTRIBUTE_DIRECTORY = 0x00000010
_WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
_WINDOWS_FILE_TYPE_DISK = 0x0001
_WINDOWS_FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
_WINDOWS_FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
_WINDOWS_FILE_FLAG_WRITE_THROUGH = 0x80000000
_WINDOWS_WRITE_DAC = 0x00040000
_WINDOWS_ERROR_FILE_NOT_FOUND = 2
_WINDOWS_ERROR_PATH_NOT_FOUND = 3
_WINDOWS_ERROR_FILE_EXISTS = 80
_WINDOWS_ERROR_ALREADY_EXISTS = 183
_WINDOWS_SE_FILE_OBJECT = 1
_WINDOWS_DACL_SECURITY_INFORMATION = 0x00000004
_WINDOWS_PROTECTED_DACL_SECURITY_INFORMATION = 0x80000000
_WINDOWS_SECURITY_INFORMATION = _WINDOWS_DACL_SECURITY_INFORMATION | _WINDOWS_PROTECTED_DACL_SECURITY_INFORMATION
_WINDOWS_SE_DACL_PROTECTED = 0x1000
_WINDOWS_ACCESS_ALLOWED_ACE_TYPE = 0
_WINDOWS_INHERITED_ACE = 0x10
_WINDOWS_FILE_ALL_ACCESS = 0x001F01FF
_WINDOWS_SYSTEM_SID = "S-1-5-18"
_ACTION_SEVERITY = {
    "allow": 0,
    "warn": 1,
    "review": 2,
    "require-reapproval": 3,
    "sandbox-required": 4,
    "block": 5,
}
# ``watch`` is observe-only; it must never override an enforcing posture when
# home/workspace policies are composed into one resident snapshot.
_POSTURE_SEVERITY = {"watch": 0, "protected": 1, "extra_careful": 2}
_SECURITY_LEVEL_SEVERITY = {
    "relaxed": 0,
    "gentle": 1,
    "balanced": 2,
    "strict": 3,
    "paranoid": 4,
    # ``custom`` is a validated configuration value whose individual floors
    # are represented by the action maps below. It must not be weakened by a
    # less-specific workspace overlay.
    "custom": 5,
}
_SANDBOX_SEVERITY = {"off": 0, "suspicious": 1, "strict": 2}
_REDACTION_SEVERITY = {"none": 0, "partial": 1, "full": 2}

_PUBLISHER_LOCK = threading.RLock()
_PUBLISHERS: dict[str, set[NativePolicySnapshotPublisher]] = {}


class NativePolicySnapshotError(RuntimeError):
    """Raised when the durable native-policy generation cannot be trusted."""


def _windows_path_has_reparse_component(path: Path) -> bool:
    """Reject final and parent reparse points before traversing a state path."""

    for candidate in (path, *path.parents):
        try:
            metadata = candidate.lstat()
        except FileNotFoundError:
            continue
        file_attributes: object = getattr(metadata, "st_file_attributes", 0)
        if candidate.is_symlink() or (
            isinstance(file_attributes, int) and bool(file_attributes & _WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT)
        ):
            return True
    return False


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


def _utf8_size_v3(value: str) -> int | None:
    try:
        return len(value.encode("utf-8"))
    except UnicodeEncodeError:
        return None


def _valid_bounded_string_v3(value: object, *, allow_empty: bool = False) -> bool:
    if not isinstance(value, str) or (not allow_empty and not value.strip()):
        return False
    size = _utf8_size_v3(value)
    return size is not None and size <= POLICY_SNAPSHOT_MAX_STRING_BYTES


def _valid_selector_key_v3(value: object) -> bool:
    if not _valid_bounded_string_v3(value):
        return False
    assert isinstance(value, str)
    return all(
        ("a" <= character <= "z") or ("A" <= character <= "Z") or ("0" <= character <= "9") or character in "_-."
        for character in value
    )


def _normalized_harness_selector_v3(value: object) -> str | None:
    if not _valid_selector_key_v3(value):
        return None
    assert isinstance(value, str)
    normalized = value.strip().lower().replace("_", "-")
    return {
        "claude": "claude-code",
        "cline-cli": "cline",
        "cline-vscode": "cline",
        "kimi-code": "kimi",
        "kimi-cli": "kimi",
        "grok-build": "grok",
        "grok-build-cli": "grok",
        "xai-grok": "grok",
        "pi-agent": "pi",
        "pi-coding-agent": "pi",
        "oh-my-pi": "omp",
        "zai": "zcode",
        "z-code": "zcode",
        "zai-zcode": "zcode",
    }.get(normalized, normalized)


def _validate_json_limits_v3(
    value: object,
    *,
    depth: int = 0,
    active_containers: set[int] | None = None,
) -> None:
    """Mirror the resident's strict JSON depth/width/string limits."""

    if depth > POLICY_SNAPSHOT_MAX_JSON_DEPTH:
        raise NativePolicySnapshotError("native_policy_snapshot_nested_depth_exceeded")
    if isinstance(value, str):
        size = _utf8_size_v3(value)
        if size is None or size > POLICY_SNAPSHOT_MAX_JSON_STRING_BYTES:
            raise NativePolicySnapshotError("native_policy_snapshot_string_too_large")
        return
    if value is None or isinstance(value, (bool, int)):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise NativePolicySnapshotError("native_policy_snapshot_number_invalid")
        return
    if not isinstance(value, (Mapping, list, tuple)):
        raise NativePolicySnapshotError("native_policy_snapshot_serialization_failed")
    containers = active_containers if active_containers is not None else set()
    identity = id(value)
    if identity in containers:
        raise NativePolicySnapshotError("native_policy_snapshot_nested_cycle")
    containers.add(identity)
    try:
        if isinstance(value, Mapping):
            if len(value) > POLICY_SNAPSHOT_MAX_JSON_COLLECTION_ITEMS:
                raise NativePolicySnapshotError("native_policy_snapshot_object_too_wide")
            for key, child in value.items():
                if not isinstance(key, str):
                    raise NativePolicySnapshotError("native_policy_snapshot_object_key_invalid")
                size = _utf8_size_v3(key)
                if size is None or size > POLICY_SNAPSHOT_MAX_JSON_STRING_BYTES:
                    raise NativePolicySnapshotError("native_policy_snapshot_key_too_large")
                _validate_json_limits_v3(child, depth=depth + 1, active_containers=containers)
        else:
            if len(value) > POLICY_SNAPSHOT_MAX_JSON_COLLECTION_ITEMS:
                raise NativePolicySnapshotError("native_policy_snapshot_array_too_wide")
            for child in value:
                _validate_json_limits_v3(child, depth=depth + 1, active_containers=containers)
    finally:
        containers.remove(identity)


def _canonical_json_bytes_v3(value: object) -> bytes:
    """Encode a JSON value exactly as the Rust canonical encoder does."""

    try:
        _validate_json_limits_v3(value)
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except NativePolicySnapshotError:
        raise
    except (TypeError, ValueError, UnicodeEncodeError, RecursionError) as error:
        raise NativePolicySnapshotError("native_policy_snapshot_serialization_failed") from error


def _digest_v3(value: object) -> str:
    return hashlib.sha256(_canonical_json_bytes_v3(value)).hexdigest()


def derive_native_policy_verifier_key(policy_integrity_key: bytes) -> bytes:
    """Derive the resident verifier without exposing the policy master key."""

    if not isinstance(policy_integrity_key, bytes) or len(policy_integrity_key) != _VERIFIER_KEY_BYTES:
        raise NativePolicySnapshotError("native_policy_verifier_master_invalid")
    return hmac.new(
        policy_integrity_key,
        POLICY_SNAPSHOT_VERIFIER_DERIVATION_DOMAIN,
        hashlib.sha256,
    ).digest()


def native_policy_verifier_key_id(verifier_key: bytes) -> str:
    if not isinstance(verifier_key, bytes) or len(verifier_key) != _VERIFIER_KEY_BYTES:
        raise NativePolicySnapshotError("native_policy_verifier_key_invalid")
    return hashlib.sha256(verifier_key).hexdigest()


def _runtime_state_directory(guard_home: Path) -> Path:
    _private_guard_home(guard_home)
    state_dir = guard_home / NATIVE_RUNTIME_STATE_DIRECTORY
    if os.name == "nt":
        _windows_ensure_private_directory(state_dir)
        return state_dir
    try:
        metadata = state_dir.lstat()
    except FileNotFoundError:
        try:
            state_dir.mkdir(mode=0o700)
        except FileExistsError:
            metadata = state_dir.lstat()
        else:
            metadata = state_dir.lstat()
    except OSError as error:
        raise NativePolicySnapshotError("native_policy_runtime_state_invalid") from error
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise NativePolicySnapshotError("native_policy_runtime_state_invalid")
    if os.name != "nt" and (metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) & 0o077):
        raise NativePolicySnapshotError("native_policy_runtime_state_not_private")
    if os.name != "nt":
        try:
            state_dir.chmod(0o700)
        except OSError as error:
            raise NativePolicySnapshotError("native_policy_runtime_state_not_private") from error
    return state_dir


def _windows_dll(name: str) -> Any:
    import ctypes

    win_dll = getattr(ctypes, "WinDLL", None)
    if not callable(win_dll):
        raise NativePolicySnapshotError("native_policy_windows_acl_unavailable")
    try:
        return win_dll(name, use_last_error=True)
    except (OSError, RuntimeError, TypeError, ValueError) as error:
        raise NativePolicySnapshotError("native_policy_windows_acl_unavailable") from error


def _windows_owner_sid() -> str:
    from .mdm.device_key_native import windows_current_user_sid

    try:
        sid = windows_current_user_sid()
    except (OSError, RuntimeError, TypeError, ValueError) as error:
        raise NativePolicySnapshotError("native_policy_windows_owner_sid_failed") from error
    if re.fullmatch(r"S-[0-9]+(?:-[0-9]+)+", sid) is None:
        raise NativePolicySnapshotError("native_policy_windows_owner_sid_invalid")
    return sid


@contextmanager
def _windows_private_descriptor(directory: bool) -> Iterator[tuple[Any, Any, Any, str]]:
    import ctypes
    from ctypes import wintypes

    advapi32 = _windows_dll("advapi32")
    kernel32 = _windows_dll("kernel32")
    owner_sid = _windows_owner_sid()
    inheritance = "OICI" if directory else ""
    sddl = f"D:P(A;{inheritance};FA;;;{owner_sid})(A;{inheritance};FA;;;{_WINDOWS_SYSTEM_SID})"
    descriptor = ctypes.c_void_p()
    descriptor_size = wintypes.DWORD()
    convert = advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW
    convert.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(wintypes.DWORD),
    ]
    convert.restype = wintypes.BOOL
    if not convert(sddl, 1, ctypes.byref(descriptor), ctypes.byref(descriptor_size)):
        raise NativePolicySnapshotError("native_policy_windows_acl_build_failed")
    local_free = kernel32.LocalFree
    local_free.argtypes = [ctypes.c_void_p]
    local_free.restype = ctypes.c_void_p
    try:
        dacl_present = wintypes.BOOL()
        dacl = ctypes.c_void_p()
        dacl_defaulted = wintypes.BOOL()
        get_dacl = advapi32.GetSecurityDescriptorDacl
        get_dacl.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(wintypes.BOOL),
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.POINTER(wintypes.BOOL),
        ]
        get_dacl.restype = wintypes.BOOL
        if (
            not get_dacl(
                descriptor,
                ctypes.byref(dacl_present),
                ctypes.byref(dacl),
                ctypes.byref(dacl_defaulted),
            )
            or not dacl_present.value
            or not dacl
        ):
            raise NativePolicySnapshotError("native_policy_windows_acl_build_failed")
        yield advapi32, descriptor, dacl, owner_sid
    finally:
        local_free(descriptor)


def _windows_file_information_type() -> Any:
    import ctypes
    from ctypes import wintypes

    class ByHandleFileInformation(ctypes.Structure):
        _fields_ = [
            ("dwFileAttributes", wintypes.DWORD),
            ("ftCreationTime", wintypes.FILETIME),
            ("ftLastAccessTime", wintypes.FILETIME),
            ("ftLastWriteTime", wintypes.FILETIME),
            ("dwVolumeSerialNumber", wintypes.DWORD),
            ("nFileSizeHigh", wintypes.DWORD),
            ("nFileSizeLow", wintypes.DWORD),
            ("nNumberOfLinks", wintypes.DWORD),
            ("nFileIndexHigh", wintypes.DWORD),
            ("nFileIndexLow", wintypes.DWORD),
        ]

    return ByHandleFileInformation


def _windows_security_attributes_type() -> Any:
    import ctypes
    from ctypes import wintypes

    class SecurityAttributes(ctypes.Structure):
        _fields_ = [
            ("nLength", wintypes.DWORD),
            ("lpSecurityDescriptor", ctypes.c_void_p),
            ("bInheritHandle", wintypes.BOOL),
        ]

    return SecurityAttributes


def _windows_open_handle(
    path: Path,
    *,
    directory: bool,
    create_new: bool = False,
    descriptor: Any | None = None,
) -> tuple[Any, Any, Any]:
    """Open/create one non-reparse Windows object while denying deletion."""

    import ctypes
    from ctypes import wintypes

    kernel32 = _windows_dll("kernel32")
    create_file = kernel32.CreateFileW
    create_file.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    create_file.restype = wintypes.HANDLE
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = [wintypes.HANDLE]
    close_handle.restype = wintypes.BOOL
    get_information = kernel32.GetFileInformationByHandle
    information_type = _windows_file_information_type()
    get_information.argtypes = [wintypes.HANDLE, ctypes.POINTER(information_type)]
    get_information.restype = wintypes.BOOL
    get_file_type = kernel32.GetFileType
    get_file_type.argtypes = [wintypes.HANDLE]
    get_file_type.restype = wintypes.DWORD
    attributes = _WINDOWS_FILE_ATTRIBUTE_NORMAL
    flags = _WINDOWS_FILE_FLAG_OPEN_REPARSE_POINT
    if directory:
        flags |= _WINDOWS_FILE_FLAG_BACKUP_SEMANTICS
        desired_access = _WINDOWS_GENERIC_READ
        share_mode = _WINDOWS_FILE_SHARE_READ | _WINDOWS_FILE_SHARE_WRITE
    else:
        desired_access = _WINDOWS_GENERIC_READ | (_WINDOWS_GENERIC_WRITE if create_new else 0)
        share_mode = _WINDOWS_FILE_SHARE_READ
    if descriptor is not None:
        # SetSecurityInfo requires WRITE_DAC on a handle. The security
        # descriptor passed to CreateFileW protects creation, while this
        # access right lets the post-create verification/application remain
        # valid on Windows instead of failing closed for every fresh file.
        desired_access |= _WINDOWS_WRITE_DAC
    if create_new:
        flags |= _WINDOWS_FILE_FLAG_WRITE_THROUGH
        disposition = _WINDOWS_CREATE_NEW
    else:
        disposition = _WINDOWS_OPEN_EXISTING
    security_attributes = None
    if descriptor is not None:
        security_attributes_type = _windows_security_attributes_type()
        security_attributes = security_attributes_type(
            ctypes.sizeof(security_attributes_type), descriptor, wintypes.BOOL(False)
        )
    handle = create_file(
        str(path),
        desired_access,
        share_mode,
        ctypes.byref(security_attributes) if security_attributes is not None else None,
        disposition,
        attributes | flags,
        None,
    )
    invalid_handle = ctypes.c_void_p(-1).value
    handle_value = getattr(handle, "value", handle)
    if handle is None or handle_value == invalid_handle:
        error_code = ctypes.get_last_error()
        if error_code in {_WINDOWS_ERROR_FILE_NOT_FOUND, _WINDOWS_ERROR_PATH_NOT_FOUND}:
            raise FileNotFoundError(str(path))
        if create_new and error_code in {_WINDOWS_ERROR_FILE_EXISTS, _WINDOWS_ERROR_ALREADY_EXISTS}:
            raise FileExistsError(str(path))
        raise NativePolicySnapshotError("native_policy_windows_path_open_failed")
    try:
        information = information_type()
        if not get_information(handle, ctypes.byref(information)):
            raise NativePolicySnapshotError("native_policy_windows_path_stat_failed")
        file_attributes = int(information.dwFileAttributes)
        expected_directory = bool(file_attributes & _WINDOWS_FILE_ATTRIBUTE_DIRECTORY)
        if (
            bool(directory) != expected_directory
            or file_attributes & _WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT
            or get_file_type(handle) != _WINDOWS_FILE_TYPE_DISK
        ):
            raise NativePolicySnapshotError("native_policy_windows_path_invalid")
        return kernel32, handle, information
    except BaseException:
        close_handle(handle)
        raise


def _windows_close_handle(kernel32: Any, handle: Any) -> None:
    from ctypes import wintypes

    close_handle = kernel32.CloseHandle
    close_handle.argtypes = [wintypes.HANDLE]
    close_handle.restype = wintypes.BOOL
    if not close_handle(handle):
        raise NativePolicySnapshotError("native_policy_windows_handle_close_failed")


def _windows_apply_private_dacl(kernel32: Any, handle: Any, descriptor: Any, dacl: Any, directory: bool) -> None:
    import ctypes
    from ctypes import wintypes

    del kernel32, descriptor, directory
    advapi32 = _windows_dll("advapi32")
    setter = advapi32.SetSecurityInfo
    setter.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
    ]
    setter.restype = wintypes.DWORD
    result = int(
        setter(
            handle,
            _WINDOWS_SE_FILE_OBJECT,
            _WINDOWS_SECURITY_INFORMATION,
            None,
            None,
            dacl,
            None,
        )
    )
    if result != 0:
        raise NativePolicySnapshotError("native_policy_windows_acl_apply_failed")


def _windows_verify_private_dacl(handle: Any, *, owner_sid: str, directory: bool) -> None:
    """Require a protected DACL containing only owner and SYSTEM full access."""

    import ctypes
    from ctypes import wintypes

    advapi32 = _windows_dll("advapi32")
    descriptor = ctypes.c_void_p()
    get_security_info = advapi32.GetSecurityInfo
    get_security_info.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
    ]
    get_security_info.restype = wintypes.DWORD
    owner = ctypes.c_void_p()
    group = ctypes.c_void_p()
    dacl = ctypes.c_void_p()
    sacl = ctypes.c_void_p()
    if (
        int(
            get_security_info(
                handle,
                _WINDOWS_SE_FILE_OBJECT,
                _WINDOWS_DACL_SECURITY_INFORMATION,
                ctypes.byref(owner),
                ctypes.byref(group),
                ctypes.byref(dacl),
                ctypes.byref(sacl),
                ctypes.byref(descriptor),
            )
        )
        != 0
        or not descriptor
        or not owner
        or not dacl
    ):
        raise NativePolicySnapshotError("native_policy_windows_acl_verify_failed")
    kernel32 = _windows_dll("kernel32")
    local_free = kernel32.LocalFree
    local_free.argtypes = [ctypes.c_void_p]
    local_free.restype = ctypes.c_void_p
    try:
        owner_sid_string = wintypes.LPWSTR()
        convert_sid = advapi32.ConvertSidToStringSidW
        convert_sid.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]
        convert_sid.restype = wintypes.BOOL
        if not convert_sid(owner, ctypes.byref(owner_sid_string)):
            raise NativePolicySnapshotError("native_policy_windows_acl_verify_failed")
        try:
            observed_owner_sid = str(owner_sid_string.value)
        finally:
            local_free(owner_sid_string)
        if observed_owner_sid != owner_sid:
            raise NativePolicySnapshotError("native_policy_windows_acl_not_private")
        control = wintypes.WORD()
        revision = wintypes.DWORD()
        get_control = advapi32.GetSecurityDescriptorControl
        get_control.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.WORD), ctypes.POINTER(wintypes.DWORD)]
        get_control.restype = wintypes.BOOL
        if not get_control(descriptor, ctypes.byref(control), ctypes.byref(revision)) or not (
            control.value & _WINDOWS_SE_DACL_PROTECTED
        ):
            raise NativePolicySnapshotError("native_policy_windows_acl_not_private")

        class AclSizeInformation(ctypes.Structure):
            _fields_ = [
                ("AceCount", wintypes.DWORD),
                ("AclBytesInUse", wintypes.DWORD),
                ("AclBytesFree", wintypes.DWORD),
            ]

        acl_info = AclSizeInformation()
        get_acl_information = advapi32.GetAclInformation
        get_acl_information.argtypes = [ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD]
        get_acl_information.restype = wintypes.BOOL
        if not get_acl_information(dacl, ctypes.byref(acl_info), ctypes.sizeof(acl_info), 2):
            raise NativePolicySnapshotError("native_policy_windows_acl_verify_failed")
        expected_sids = {owner_sid, _WINDOWS_SYSTEM_SID}
        seen_sids: set[str] = set()
        for index in range(int(acl_info.AceCount)):
            ace = ctypes.c_void_p()
            get_ace = advapi32.GetAce
            get_ace.argtypes = [ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p)]
            get_ace.restype = wintypes.BOOL
            if not get_ace(dacl, index, ctypes.byref(ace)) or not ace:
                raise NativePolicySnapshotError("native_policy_windows_acl_verify_failed")
            address = ace.value
            if not isinstance(address, int):
                raise NativePolicySnapshotError("native_policy_windows_acl_verify_failed")
            ace_type = ctypes.c_ubyte.from_address(address).value
            ace_flags = ctypes.c_ubyte.from_address(address + 1).value
            ace_size = ctypes.c_ushort.from_address(address + 2).value
            mask = ctypes.c_uint32.from_address(address + 4).value
            expected_flags = 0x03 if directory else 0
            if (
                ace_type != _WINDOWS_ACCESS_ALLOWED_ACE_TYPE
                or ace_flags != expected_flags
                or ace_flags & _WINDOWS_INHERITED_ACE
                or ace_size < 12
                or mask != _WINDOWS_FILE_ALL_ACCESS
            ):
                raise NativePolicySnapshotError("native_policy_windows_acl_not_private")
            sid_pointer = ctypes.c_void_p(address + 8)
            sid_string = wintypes.LPWSTR()
            if not convert_sid(sid_pointer, ctypes.byref(sid_string)):
                raise NativePolicySnapshotError("native_policy_windows_acl_verify_failed")
            try:
                sid = str(sid_string.value)
            finally:
                local_free(sid_string)
            if sid not in expected_sids or sid in seen_sids:
                raise NativePolicySnapshotError("native_policy_windows_acl_not_private")
            seen_sids.add(sid)
        required_sids = {_WINDOWS_SYSTEM_SID} if owner_sid == _WINDOWS_SYSTEM_SID else expected_sids
        if seen_sids != required_sids:
            raise NativePolicySnapshotError("native_policy_windows_acl_not_private")
    finally:
        local_free(descriptor)


def _windows_ensure_private_directory(path: Path) -> None:
    import ctypes
    from ctypes import wintypes

    created = False
    try:
        with _windows_private_descriptor(True) as (_advapi32, descriptor, dacl, owner_sid):
            kernel32 = _windows_dll("kernel32")
            create_directory = kernel32.CreateDirectoryW
            create_directory.argtypes = [wintypes.LPCWSTR, ctypes.c_void_p]
            create_directory.restype = wintypes.BOOL
            security_attributes_type = _windows_security_attributes_type()
            security_attributes = security_attributes_type(
                ctypes.sizeof(security_attributes_type), descriptor, wintypes.BOOL(False)
            )
            if create_directory(str(path), ctypes.byref(security_attributes)):
                created = True
            elif ctypes.get_last_error() != _WINDOWS_ERROR_ALREADY_EXISTS:
                raise NativePolicySnapshotError("native_policy_windows_state_directory_create_failed")
        kernel32, handle, _information = _windows_open_handle(path, directory=True)
        try:
            if created:
                with _windows_private_descriptor(True) as (_advapi32, descriptor, dacl, _owner_sid):
                    _windows_apply_private_dacl(kernel32, handle, descriptor, dacl, True)
            _windows_verify_private_dacl(handle, owner_sid=owner_sid, directory=True)
        finally:
            _windows_close_handle(kernel32, handle)
    except NativePolicySnapshotError:
        raise
    except (OSError, RuntimeError, TypeError, ValueError) as error:
        raise NativePolicySnapshotError("native_policy_windows_state_directory_invalid") from error


def _windows_read_key(path: Path, expected: bytes) -> None:
    import ctypes
    from ctypes import wintypes

    kernel32, handle, information = _windows_open_handle(path, directory=False)
    try:
        owner_sid = _windows_owner_sid()
        _windows_verify_private_dacl(handle, owner_sid=owner_sid, directory=False)
        size = (int(information.nFileSizeHigh) << 32) | int(information.nFileSizeLow)
        if size != _VERIFIER_KEY_BYTES:
            raise NativePolicySnapshotError("native_policy_verifier_key_invalid")
        read_file = kernel32.ReadFile
        read_file.argtypes = [
            wintypes.HANDLE,
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
            ctypes.c_void_p,
        ]
        read_file.restype = wintypes.BOOL
        buffer = (ctypes.c_ubyte * (_VERIFIER_KEY_BYTES + 1))()
        count = wintypes.DWORD()
        if (
            not read_file(
                handle,
                buffer,
                _VERIFIER_KEY_BYTES + 1,
                ctypes.byref(count),
                None,
            )
            or count.value != _VERIFIER_KEY_BYTES
        ):
            raise NativePolicySnapshotError("native_policy_verifier_key_read_failed")
        if not hmac.compare_digest(bytes(buffer[: count.value]), expected):
            raise NativePolicySnapshotError("native_policy_verifier_key_mismatch")
    finally:
        _windows_close_handle(kernel32, handle)


def _windows_provision_verifier_key(path: Path, derived: bytes) -> Path:
    import ctypes
    from ctypes import wintypes

    try:
        _windows_read_key(path, derived)
        return path
    except FileNotFoundError:
        pass
    owner_sid = _windows_owner_sid()
    try:
        with _windows_private_descriptor(False) as (_advapi32, descriptor, dacl, _descriptor_owner_sid):
            kernel32, handle, _information = _windows_open_handle(
                path,
                directory=False,
                create_new=True,
                descriptor=descriptor,
            )
            try:
                write_file = kernel32.WriteFile
                write_file.argtypes = [
                    wintypes.HANDLE,
                    ctypes.c_void_p,
                    wintypes.DWORD,
                    ctypes.POINTER(wintypes.DWORD),
                    ctypes.c_void_p,
                ]
                write_file.restype = wintypes.BOOL
                buffer = (ctypes.c_ubyte * len(derived)).from_buffer_copy(derived)
                count = wintypes.DWORD()
                if not write_file(
                    handle,
                    buffer,
                    len(derived),
                    ctypes.byref(count),
                    None,
                ) or count.value != len(derived):
                    raise NativePolicySnapshotError("native_policy_verifier_key_write_failed")
                flush = kernel32.FlushFileBuffers
                flush.argtypes = [wintypes.HANDLE]
                flush.restype = wintypes.BOOL
                if not flush(handle):
                    raise NativePolicySnapshotError("native_policy_verifier_key_sync_failed")
                _windows_apply_private_dacl(kernel32, handle, descriptor, dacl, False)
                _windows_verify_private_dacl(handle, owner_sid=owner_sid, directory=False)
            finally:
                _windows_close_handle(kernel32, handle)
    except FileExistsError:
        _windows_read_key(path, derived)
        return path
    except NativePolicySnapshotError:
        raise
    except (OSError, RuntimeError, TypeError, ValueError) as error:
        raise NativePolicySnapshotError("native_policy_verifier_key_write_failed") from error
    return path


def provision_native_policy_verifier_key(
    guard_home: Path,
    policy_integrity_key: bytes,
) -> Path:
    """Provision the owner-private derived key consumed by the Rust resident.

    Creation uses ``O_EXCL`` and never replaces an existing key. A changed
    policy master is therefore a safe failure requiring explicit repair rather
    than an implicit verifier reset that could invalidate the resident floor.
    """

    derived = derive_native_policy_verifier_key(policy_integrity_key)
    state_dir = _runtime_state_directory(guard_home)
    path = state_dir / NATIVE_POLICY_VERIFIER_KEY_NAME
    if os.name == "nt":
        return _windows_provision_verifier_key(path, derived)
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        metadata = None
    except OSError as error:
        raise NativePolicySnapshotError("native_policy_verifier_key_stat_failed") from error

    if metadata is not None:
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            raise NativePolicySnapshotError("native_policy_verifier_key_invalid")
        if metadata.st_size != _VERIFIER_KEY_BYTES:
            raise NativePolicySnapshotError("native_policy_verifier_key_invalid")
        if os.name != "nt" and (metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) & 0o077):
            raise NativePolicySnapshotError("native_policy_verifier_key_not_private")
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(path, flags)
        except OSError as error:
            raise NativePolicySnapshotError("native_policy_verifier_key_read_failed") from error
        try:
            opened = os.fstat(descriptor)
            existing = os.read(descriptor, _VERIFIER_KEY_BYTES + 1)
        finally:
            os.close(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_size != _VERIFIER_KEY_BYTES
            or len(existing) != _VERIFIER_KEY_BYTES
            or not hmac.compare_digest(existing, derived)
        ):
            raise NativePolicySnapshotError("native_policy_verifier_key_mismatch")
        return path

    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, 0o600)
    except FileExistsError:
        # Another process won the race. Re-enter the validation path without
        # replacing or weakening its key.
        return provision_native_policy_verifier_key(guard_home, policy_integrity_key)
    except OSError as error:
        raise NativePolicySnapshotError("native_policy_verifier_key_write_failed") from error
    try:
        written = 0
        while written < len(derived):
            written += os.write(descriptor, derived[written:])
        os.fsync(descriptor)
    except OSError as error:
        raise NativePolicySnapshotError("native_policy_verifier_key_write_failed") from error
    finally:
        os.close(descriptor)
    if os.name != "nt":
        try:
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
            raise NativePolicySnapshotError("native_policy_verifier_key_sync_failed") from error
    return path


def _normalize_scope_text_v3(value: str) -> str:
    """Canonicalize a guard-home identity across Windows path aliases."""
    if os.name == "nt":
        normalized = value.replace("/", "\\")
        folded = normalized.casefold()
        if folded.startswith("\\\\?\\unc\\"):
            normalized = "\\\\" + normalized[8:]
        elif folded.startswith("\\\\?\\"):
            normalized = normalized[4:]
        while len(normalized) > 3 and normalized.endswith("\\"):
            normalized = normalized[:-1]
        return normalized.casefold()
    if value.startswith("/private/"):
        return value[len("/private") :]
    return value


def _scope_digest_v3(guard_home: Path) -> str:
    try:
        canonical = str(guard_home.expanduser().resolve(strict=False))
    except (OSError, RuntimeError, ValueError):
        canonical = str(guard_home)
    canonical = _normalize_scope_text_v3(canonical)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _config_value(config: GuardConfig | Mapping[str, object], name: str, default: object = None) -> object:
    if isinstance(config, Mapping):
        return config.get(name, default)
    return getattr(config, name, default)


def _action_value(config: GuardConfig | Mapping[str, object], name: str, default: str) -> str:
    value = _config_value(config, name, default)
    if not isinstance(value, str) or value not in _VALID_ACTIONS:
        raise NativePolicySnapshotError("native_policy_snapshot_policy_invalid")
    return value


def _string_map(value: object, *, risk_keys: bool = False, selector_keys: bool = False) -> dict[str, str]:
    if value is None:
        return {}
    if not isinstance(value, Mapping) or len(value) > POLICY_SNAPSHOT_MAX_MAP_ENTRIES:
        raise NativePolicySnapshotError("native_policy_snapshot_policy_invalid")
    result: dict[str, str] = {}
    for key, action in value.items():
        if (
            not _valid_bounded_string_v3(key)
            or (selector_keys and not _valid_selector_key_v3(key))
            or (risk_keys and key not in _VALID_RISK_ACTION_KEYS)
            or not isinstance(action, str)
            or action not in _VALID_ACTIONS
        ):
            raise NativePolicySnapshotError("native_policy_snapshot_policy_invalid")
        assert isinstance(key, str)
        result[key] = action
    return result


def _harness_risk_map(value: object) -> dict[str, dict[str, str]]:
    if value is None:
        return {}
    if not isinstance(value, Mapping) or len(value) > POLICY_SNAPSHOT_MAX_HARNESS_ENTRIES:
        raise NativePolicySnapshotError("native_policy_snapshot_policy_invalid")
    result: dict[str, dict[str, str]] = {}
    for harness, actions in value.items():
        if not _valid_selector_key_v3(harness):
            raise NativePolicySnapshotError("native_policy_snapshot_policy_invalid")
        assert isinstance(harness, str)
        canonical = _normalized_harness_selector_v3(harness)
        if canonical is None:
            raise NativePolicySnapshotError("native_policy_snapshot_policy_invalid")
        current = _string_map(actions, risk_keys=True)
        previous = next(
            (existing for key, existing in result.items() if _normalized_harness_selector_v3(key) == canonical),
            None,
        )
        if previous is not None and previous != current:
            raise NativePolicySnapshotError("native_policy_snapshot_policy_invalid")
        result[harness] = current
    return result


def _harness_action_map(value: object) -> dict[str, str]:
    result = _string_map(value, selector_keys=True)
    canonical: dict[str, str] = {}
    for key, action in result.items():
        normalized = _normalized_harness_selector_v3(key)
        if normalized is None:
            raise NativePolicySnapshotError("native_policy_snapshot_policy_invalid")
        previous = canonical.get(normalized)
        if previous is not None and previous != action:
            raise NativePolicySnapshotError("native_policy_snapshot_policy_invalid")
        canonical[normalized] = action
    return result


def effective_native_policy_v3(config: GuardConfig | Mapping[str, object]) -> dict[str, object]:
    """Build the bounded effective policy consumed by native hook decisions."""

    risk_value: object = _config_value(config, "risk_actions")
    if not isinstance(config, Mapping):
        # The posture/level defaults are enforcement inputs even when no TOML
        # risk_actions override exists. Keep this import lazy to avoid a
        # config/native-runtime import cycle during ordinary hook startup.
        from .config import _effective_risk_actions

        risk_value = _effective_risk_actions(config)
    else:
        risk_value = risk_value or {}
    posture = _config_value(config, "protection_posture", "protected")
    security_level = _config_value(config, "security_level", "balanced")
    sandbox_analysis = _config_value(config, "sandbox_analysis", "off")
    redaction_level = _config_value(config, "receipt_redaction_level", "full")
    if (
        not isinstance(posture, str)
        or posture not in _VALID_POSTURES
        or not isinstance(security_level, str)
        or security_level not in _VALID_SECURITY_LEVELS
        or not isinstance(sandbox_analysis, str)
        or sandbox_analysis not in _VALID_SANDBOX_ANALYSIS
        or not isinstance(redaction_level, str)
        or redaction_level not in _VALID_REDACTION_LEVELS
    ):
        raise NativePolicySnapshotError("native_policy_snapshot_policy_invalid")
    return {
        "protection_posture": posture,
        "security_level": security_level,
        "default_action": _action_value(config, "default_action", "warn"),
        "unknown_publisher_action": _action_value(config, "unknown_publisher_action", "review"),
        "changed_hash_action": _action_value(config, "changed_hash_action", "require-reapproval"),
        "new_network_domain_action": _action_value(config, "new_network_domain_action", "warn"),
        "subprocess_action": _action_value(config, "subprocess_action", "warn"),
        "risk_actions": _string_map(risk_value, risk_keys=True),
        "harness_risk_actions": _harness_risk_map(_config_value(config, "harness_risk_actions")),
        "harness_actions": _harness_action_map(_config_value(config, "harness_actions")),
        "publisher_actions": _string_map(_config_value(config, "publisher_actions")),
        "artifact_actions": _string_map(_config_value(config, "artifact_actions")),
        "sandbox_analysis": sandbox_analysis,
        "receipt_redaction_level": redaction_level,
    }


def _snapshot_policy_digest_v3(
    *,
    config_digest: str,
    effective_policy: Mapping[str, object],
    mode: str,
    rule_digest: str,
    runtime_identity: str,
    scope_digest: str,
) -> str:
    return _digest_v3(
        {
            "config_digest": config_digest,
            "effective_policy_digest": _digest_v3(effective_policy),
            "mode": mode,
            "protocol_version": POLICY_SNAPSHOT_PROTOCOL_VERSION,
            "rule_digest": rule_digest,
            "runtime_identity": runtime_identity,
            "scope_digest": scope_digest,
            "version": POLICY_SNAPSHOT_V3_VERSION,
        }
    )


def _require_snapshot_mapping_fields_v3(value: object, fields: frozenset[str]) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise NativePolicySnapshotError("native_policy_snapshot_unknown_field")
    return value


def _valid_u16_v3(value: object) -> bool:
    return type(value) is int and 0 <= value <= _MAX_U16


def _valid_u64_v3(value: object) -> bool:
    return type(value) is int and 0 <= value <= _MAX_U64


def _validate_snapshot_v3(
    snapshot: Mapping[str, object],
    *,
    allow_empty_mac: bool = False,
    verify_digests: bool = True,
) -> None:
    """Apply the resident's typed v3 validation before signing or transport."""

    _validate_json_limits_v3(snapshot)
    root = _require_snapshot_mapping_fields_v3(snapshot, _SNAPSHOT_FIELDS)
    if root.get("schema") != POLICY_SNAPSHOT_V3_SCHEMA:
        raise NativePolicySnapshotError("native_policy_snapshot_schema_invalid")
    if not _valid_u16_v3(root.get("version")) or root.get("version") != POLICY_SNAPSHOT_V3_VERSION:
        raise NativePolicySnapshotError("native_policy_snapshot_version_invalid")
    if not _valid_u64_v3(root.get("generation")) or root.get("generation") == 0:
        raise NativePolicySnapshotError("native_policy_snapshot_generation_invalid")
    for field in ("policy_digest", "config_digest", "rule_digest", "runtime_identity"):
        if not _valid_digest_v3(root.get(field)):
            raise NativePolicySnapshotError("native_policy_snapshot_digest_invalid")
    if (
        not _valid_u16_v3(root.get("protocol_version"))
        or root.get("protocol_version") != POLICY_SNAPSHOT_PROTOCOL_VERSION
    ):
        raise NativePolicySnapshotError("native_policy_snapshot_protocol_invalid")
    mode = root.get("mode")
    if not _valid_bounded_string_v3(mode) or mode not in {"enforce", "observe"}:
        raise NativePolicySnapshotError("native_policy_snapshot_mode_invalid")
    if not _valid_u64_v3(root.get("issued_at_ms")) or not _valid_u64_v3(root.get("expires_at_ms")):
        raise NativePolicySnapshotError("native_policy_snapshot_expiry_invalid")
    issued = cast(int, root["issued_at_ms"])
    expires = cast(int, root["expires_at_ms"])
    if expires <= issued or expires - issued > POLICY_SNAPSHOT_MAX_EXPIRY_MS:
        raise NativePolicySnapshotError("native_policy_snapshot_expiry_invalid")

    scope = _require_snapshot_mapping_fields_v3(root.get("scope_contract"), _SCOPE_FIELDS)
    if (
        not _valid_bounded_string_v3(scope.get("schema"))
        or scope.get("schema") != "guard-native-scope.v1"
        or not _valid_bounded_string_v3(scope.get("kind"))
        or scope.get("kind") != "guard-home"
        or not _valid_bounded_string_v3(scope.get("workspace_binding"))
        or scope.get("workspace_binding") != "request-source"
        or not _valid_digest_v3(scope.get("scope_digest"))
    ):
        raise NativePolicySnapshotError("native_policy_snapshot_scope_invalid")

    effective = _require_snapshot_mapping_fields_v3(root.get("effective_policy"), _EFFECTIVE_POLICY_FIELDS)
    for field in ("protection_posture", "security_level", "sandbox_analysis", "receipt_redaction_level"):
        if not _valid_bounded_string_v3(effective.get(field)):
            raise NativePolicySnapshotError("native_policy_snapshot_policy_invalid")
    if (
        effective.get("protection_posture") not in _VALID_POSTURES
        or effective.get("security_level") not in _VALID_SECURITY_LEVELS
        or effective.get("sandbox_analysis") not in _VALID_SANDBOX_ANALYSIS
        or effective.get("receipt_redaction_level") not in _VALID_REDACTION_LEVELS
    ):
        raise NativePolicySnapshotError("native_policy_snapshot_policy_invalid")
    for field in (
        "default_action",
        "unknown_publisher_action",
        "changed_hash_action",
        "new_network_domain_action",
        "subprocess_action",
    ):
        if not isinstance(effective.get(field), str) or effective[field] not in _VALID_ACTIONS:
            raise NativePolicySnapshotError("native_policy_snapshot_policy_invalid")

    risk_actions = effective.get("risk_actions")
    harness_risk_actions = effective.get("harness_risk_actions")
    harness_actions = effective.get("harness_actions")
    publisher_actions = effective.get("publisher_actions")
    artifact_actions = effective.get("artifact_actions")
    if not isinstance(risk_actions, Mapping) or not isinstance(harness_risk_actions, Mapping):
        raise NativePolicySnapshotError("native_policy_snapshot_policy_invalid")
    if not isinstance(harness_actions, Mapping):
        raise NativePolicySnapshotError("native_policy_snapshot_policy_invalid")
    if not isinstance(publisher_actions, Mapping) or not isinstance(artifact_actions, Mapping):
        raise NativePolicySnapshotError("native_policy_snapshot_policy_invalid")
    _string_map(risk_actions, risk_keys=True)
    _harness_risk_map(harness_risk_actions)
    _harness_action_map(harness_actions)
    _string_map(publisher_actions)
    _string_map(artifact_actions)

    integrity = _require_snapshot_mapping_fields_v3(root.get("integrity"), _INTEGRITY_FIELDS)
    if (
        not _valid_bounded_string_v3(integrity.get("algorithm"))
        or integrity.get("algorithm") != POLICY_SNAPSHOT_INTEGRITY_ALGORITHM
        or not _valid_digest_v3(integrity.get("key_id"))
    ):
        raise NativePolicySnapshotError("native_policy_snapshot_integrity_invalid")
    mac = integrity.get("mac")
    if not (allow_empty_mac and mac == "") and not _valid_digest_v3(mac):
        raise NativePolicySnapshotError("native_policy_snapshot_integrity_invalid")

    if verify_digests:
        effective_digest = _digest_v3(effective)
        if root.get("config_digest") != effective_digest:
            raise NativePolicySnapshotError("native_policy_snapshot_digest_mismatch")
        expected_policy_digest = _snapshot_policy_digest_v3(
            config_digest=cast(str, root["config_digest"]),
            effective_policy=effective,
            mode=cast(str, mode),
            rule_digest=cast(str, root["rule_digest"]),
            runtime_identity=cast(str, root["runtime_identity"]),
            scope_digest=cast(str, scope["scope_digest"]),
        )
        if root.get("policy_digest") != expected_policy_digest:
            raise NativePolicySnapshotError("native_policy_snapshot_digest_mismatch")


def _snapshot_integrity_mac_v3(snapshot: Mapping[str, object], verifier_key: bytes) -> str:
    _validate_snapshot_v3(snapshot, allow_empty_mac=True)
    signing_value = dict(snapshot)
    signing_value.pop("integrity", None)
    return hmac.new(
        verifier_key,
        POLICY_SNAPSHOT_INTEGRITY_DOMAIN + _canonical_json_bytes_v3(signing_value),
        hashlib.sha256,
    ).hexdigest()


def _valid_digest_v3(value: object) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(character in "0123456789abcdef" for character in value)


def build_policy_snapshot_v3(
    *,
    config: GuardConfig | Mapping[str, object],
    guard_home: Path,
    runtime_identity: str,
    rule_digest: str,
    verifier_key: bytes,
    generation: int,
    issued_at_ms: int | None = None,
    expires_at_ms: int | None = None,
) -> dict[str, object]:
    """Build and authenticate one Rust ``PolicySnapshotV3`` value."""

    if (
        isinstance(generation, bool)
        or not isinstance(generation, int)
        or generation <= 0
        or not _valid_digest_v3(runtime_identity)
        or not _valid_digest_v3(rule_digest)
    ):
        raise NativePolicySnapshotError("native_policy_snapshot_identity_invalid")
    if not isinstance(verifier_key, bytes) or len(verifier_key) != _VERIFIER_KEY_BYTES:
        raise NativePolicySnapshotError("native_policy_verifier_key_invalid")
    effective_policy = effective_native_policy_v3(config)
    raw_mode = _config_value(config, "mode", "prompt")
    if not isinstance(raw_mode, str) or raw_mode not in _VALID_INPUT_MODES:
        raise NativePolicySnapshotError("native_policy_snapshot_mode_invalid")
    mode = "observe" if raw_mode == "observe" or effective_policy["protection_posture"] == "watch" else "enforce"
    scope_digest = _scope_digest_v3(guard_home)
    config_digest = _digest_v3(effective_policy)
    policy_digest = _snapshot_policy_digest_v3(
        config_digest=config_digest,
        effective_policy=effective_policy,
        mode=mode,
        rule_digest=rule_digest,
        runtime_identity=runtime_identity,
        scope_digest=scope_digest,
    )
    issued = int(time.time() * 1_000) if issued_at_ms is None else issued_at_ms
    expires = issued + POLICY_SNAPSHOT_MAX_EXPIRY_MS if expires_at_ms is None else expires_at_ms
    if (
        isinstance(issued, bool)
        or not isinstance(issued, int)
        or isinstance(expires, bool)
        or not isinstance(expires, int)
        or expires <= issued
        or expires - issued > POLICY_SNAPSHOT_MAX_EXPIRY_MS
    ):
        raise NativePolicySnapshotError("native_policy_snapshot_expiry_invalid")
    snapshot: dict[str, object] = {
        "schema": POLICY_SNAPSHOT_V3_SCHEMA,
        "version": POLICY_SNAPSHOT_V3_VERSION,
        "generation": generation,
        "policy_digest": policy_digest,
        "config_digest": config_digest,
        "rule_digest": rule_digest,
        "runtime_identity": runtime_identity,
        "protocol_version": POLICY_SNAPSHOT_PROTOCOL_VERSION,
        "mode": mode,
        "scope_contract": {
            "schema": "guard-native-scope.v1",
            "kind": "guard-home",
            "scope_digest": scope_digest,
            "workspace_binding": "request-source",
        },
        "effective_policy": effective_policy,
        "issued_at_ms": issued,
        "expires_at_ms": expires,
        "integrity": {
            "algorithm": POLICY_SNAPSHOT_INTEGRITY_ALGORITHM,
            "key_id": native_policy_verifier_key_id(verifier_key),
            "mac": "",
        },
    }
    _validate_snapshot_v3(snapshot, allow_empty_mac=True)
    integrity = cast(dict[str, object], snapshot["integrity"])
    # The MAC is a fixed-size lowercase hex string. Validate the complete
    # canonical size with that exact placeholder before spending CPU on the
    # signing operation; Rust rejects the same 256 KiB boundary.
    integrity["mac"] = "0" * 64
    _validate_snapshot_v3(snapshot)
    if len(_canonical_json_bytes_v3(snapshot)) > POLICY_SNAPSHOT_MAX_BYTES:
        raise NativePolicySnapshotError("native_policy_snapshot_too_large")
    integrity["mac"] = _snapshot_integrity_mac_v3(snapshot, verifier_key)
    _validate_snapshot_v3(snapshot)
    encoded = _canonical_json_bytes_v3(snapshot)
    if len(encoded) > POLICY_SNAPSHOT_MAX_BYTES:
        raise NativePolicySnapshotError("native_policy_snapshot_too_large")
    return snapshot


def snapshot_config_digest_v3(snapshot: Mapping[str, object]) -> str:
    _validate_snapshot_v3(snapshot)
    effective_policy = snapshot["effective_policy"]
    assert isinstance(effective_policy, Mapping)
    return _digest_v3(effective_policy)


def snapshot_signing_bytes_v3(snapshot: Mapping[str, object]) -> bytes:
    _validate_snapshot_v3(snapshot, allow_empty_mac=True)
    value = dict(snapshot)
    value.pop("integrity", None)
    return _canonical_json_bytes_v3(value)


def snapshot_bytes_v3(snapshot: Mapping[str, object]) -> bytes:
    _validate_snapshot_v3(snapshot)
    encoded = _canonical_json_bytes_v3(snapshot)
    if len(encoded) > POLICY_SNAPSHOT_MAX_BYTES:
        raise NativePolicySnapshotError("native_policy_snapshot_too_large")
    return encoded


def _policy_snapshot_push_bytes_v3(snapshot: Mapping[str, object]) -> bytes:
    """Build the strict resident push envelope after validating its snapshot."""

    _validate_snapshot_v3(snapshot)
    envelope = {
        "operation": "policy_snapshot_push",
        "deadline_budget_ms": int(_PUBLISH_TIMEOUT_SECONDS * 1_000),
        "request": {"schema": POLICY_SNAPSHOT_PUSH_SCHEMA, "snapshot": snapshot},
    }
    _require_snapshot_mapping_fields_v3(envelope, _PUSH_ENVELOPE_FIELDS)
    request = envelope["request"]
    request_mapping = _require_snapshot_mapping_fields_v3(request, _PUSH_REQUEST_FIELDS)
    if (
        envelope["operation"] != "policy_snapshot_push"
        or type(envelope["deadline_budget_ms"]) is not int
        or not 1 <= envelope["deadline_budget_ms"] <= 9_000
        or request_mapping.get("schema") != POLICY_SNAPSHOT_PUSH_SCHEMA
    ):
        raise NativePolicySnapshotError("native_policy_snapshot_push_invalid")
    encoded = _canonical_json_bytes_v3(envelope)
    if len(encoded) > POLICY_SNAPSHOT_MAX_BYTES:
        raise NativePolicySnapshotError("native_policy_snapshot_too_large")
    return encoded


def _strict_json_loads_v3(payload: bytes) -> object:
    def reject_duplicate_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
        keys: set[str] = set()
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in keys:
                raise NativePolicySnapshotError("native_policy_snapshot_duplicate_key")
            keys.add(key)
            result[key] = value
        return result

    try:
        return json.loads(payload.decode("utf-8"), object_pairs_hook=reject_duplicate_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise NativePolicySnapshotError("native_policy_snapshot_json_invalid") from error


def _snapshot_cache_path_v3(guard_home: Path) -> Path:
    return _runtime_state_directory(guard_home) / NATIVE_POLICY_SNAPSHOT_CACHE_NAME


def _windows_read_snapshot_bytes(path: Path) -> bytes | None:
    """Read one cache object from a single verified non-reparse handle."""

    import ctypes
    from ctypes import wintypes

    try:
        kernel32, handle, information = _windows_open_handle(path, directory=False)
    except FileNotFoundError:
        return None
    try:
        owner_sid = _windows_owner_sid()
        _windows_verify_private_dacl(handle, owner_sid=owner_sid, directory=False)
        expected_size = (int(information.nFileSizeHigh) << 32) | int(information.nFileSizeLow)
        if expected_size <= 0 or expected_size > POLICY_SNAPSHOT_MAX_BYTES:
            raise NativePolicySnapshotError("native_policy_snapshot_cache_invalid")
        read_file = kernel32.ReadFile
        read_file.argtypes = [
            wintypes.HANDLE,
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
            ctypes.c_void_p,
        ]
        read_file.restype = wintypes.BOOL
        buffer = (ctypes.c_ubyte * (POLICY_SNAPSHOT_MAX_BYTES + 1))()
        total = 0
        while total <= POLICY_SNAPSHOT_MAX_BYTES:
            request_size = min(64 * 1024, POLICY_SNAPSHOT_MAX_BYTES + 1 - total)
            if request_size <= 0:
                break
            count = wintypes.DWORD()
            if not read_file(
                handle,
                ctypes.byref(buffer, total),
                request_size,
                ctypes.byref(count),
                None,
            ):
                raise NativePolicySnapshotError("native_policy_snapshot_cache_read_failed")
            chunk_size = int(count.value)
            if chunk_size < 0 or chunk_size > request_size:
                raise NativePolicySnapshotError("native_policy_snapshot_cache_read_failed")
            if chunk_size == 0:
                break
            total += chunk_size
        if total != expected_size or total > POLICY_SNAPSHOT_MAX_BYTES:
            raise NativePolicySnapshotError("native_policy_snapshot_cache_invalid")
        return bytes(buffer[:total])
    finally:
        _windows_close_handle(kernel32, handle)


def _read_v3_snapshot_file(
    path: Path,
    *,
    verifier_key: bytes | None = None,
) -> tuple[dict[str, object], bytes] | None:
    """Read one exact canonical snapshot from a private state file."""

    if os.name == "nt" and _windows_path_has_reparse_component(path):
        raise NativePolicySnapshotError("native_policy_snapshot_cache_invalid")
    if os.name == "nt":
        payload = _windows_read_snapshot_bytes(path)
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
                or metadata.st_size > POLICY_SNAPSHOT_MAX_BYTES
                or (metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) & 0o077)
            ):
                raise NativePolicySnapshotError("native_policy_snapshot_cache_invalid")
            payload = bytearray()
            while len(payload) <= POLICY_SNAPSHOT_MAX_BYTES:
                chunk = os.read(descriptor, min(64 * 1024, POLICY_SNAPSHOT_MAX_BYTES + 1 - len(payload)))
                if not chunk:
                    break
                payload.extend(chunk)
            if len(payload) != metadata.st_size or len(payload) > POLICY_SNAPSHOT_MAX_BYTES:
                raise NativePolicySnapshotError("native_policy_snapshot_cache_invalid")
        except OSError as error:
            raise NativePolicySnapshotError("native_policy_snapshot_cache_read_failed") from error
        finally:
            os.close(descriptor)
        payload = bytes(payload)
    value = _strict_json_loads_v3(payload)
    if not isinstance(value, dict):
        raise NativePolicySnapshotError("native_policy_snapshot_cache_invalid")
    _validate_snapshot_v3(value)
    canonical = snapshot_bytes_v3(value)
    if canonical != payload:
        raise NativePolicySnapshotError("native_policy_snapshot_cache_noncanonical")
    if verifier_key is not None:
        integrity = value.get("integrity")
        if not isinstance(integrity, Mapping) or not hmac.compare_digest(
            cast(str, integrity.get("mac")),
            _snapshot_integrity_mac_v3(value, verifier_key),
        ):
            raise NativePolicySnapshotError("native_policy_snapshot_cache_integrity_invalid")
    return cast(dict[str, object], value), payload


def _read_v3_snapshot_cache(
    guard_home: Path,
    *,
    verifier_key: bytes | None = None,
) -> tuple[dict[str, object], bytes] | None:
    """Read the exact canonical snapshot retained across publisher restarts."""

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

    payload = snapshot_bytes_v3(snapshot)
    state_dir = _runtime_state_directory(guard_home)
    path = state_dir / name
    if os.name == "nt" and _windows_path_has_reparse_component(path):
        raise NativePolicySnapshotError("native_policy_snapshot_cache_invalid")
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
        if os.name != "nt":
            path.chmod(0o600)
            directory_descriptor = os.open(
                state_dir,
                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0),
            )
            try:
                os.fsync(directory_descriptor)
            finally:
                os.close(directory_descriptor)
        else:
            owner_sid = _windows_owner_sid()
            kernel32, handle, _information = _windows_open_handle(path, directory=False)
            try:
                _windows_verify_private_dacl(handle, owner_sid=owner_sid, directory=False)
            finally:
                _windows_close_handle(kernel32, handle)
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
    with suppress(FileNotFoundError):
        _snapshot_pending_path_v3(guard_home).unlink()


def _recover_v3_snapshot_transaction(guard_home: Path, verifier_key: bytes) -> None:
    """Complete a snapshot/cache transaction left by a process crash."""

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
    _private_guard_home(guard_home)
    path = guard_home / _V3_GENERATION_LOCK_NAME
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as error:
        raise NativePolicySnapshotError("native_policy_snapshot_generation_lock_invalid") from error
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise NativePolicySnapshotError("native_policy_snapshot_generation_lock_invalid")
        if os.name != "nt" and (metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) & 0o077):
            raise NativePolicySnapshotError("native_policy_snapshot_generation_lock_invalid")
        if metadata.st_size == 0:
            os.write(descriptor, b"0")
            os.fsync(descriptor)
        deadline = deadline_monotonic if deadline_monotonic is not None else time.monotonic() + 1.0
        if os.name != "nt":
            import fcntl

            while True:
                try:
                    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
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
                    os.lseek(descriptor, 0, os.SEEK_SET)
                    msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
                    break
                except OSError as error:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise NativePolicySnapshotError("native_policy_snapshot_generation_lock_timeout") from error
                    time.sleep(min(0.01, remaining))
        try:
            yield descriptor
        finally:
            if os.name != "nt":
                import fcntl

                fcntl.flock(descriptor, fcntl.LOCK_UN)
            else:
                import msvcrt

                os.lseek(descriptor, 0, os.SEEK_SET)
                msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
    finally:
        os.close(descriptor)


def _read_v3_generation_state(guard_home: Path) -> tuple[int, str] | None:
    path = guard_home / _V3_GENERATION_STATE_NAME
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
            or (os.name != "nt" and (metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) & 0o077))
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
    value = {"generation": generation, "policy_digest": policy_digest, "schema": _V3_GENERATION_SCHEMA}
    payload = _canonical_json_bytes_v3(value)
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
        if os.name != "nt":
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


def _v3_generation_for_policy(
    guard_home: Path,
    policy_digest: str,
    *,
    deadline_monotonic: float | None,
    force_increment: bool = False,
    minimum_generation: int | None = None,
    lock_descriptor: int | None = None,
    persist_state: bool = True,
) -> int:
    _private_guard_home(guard_home)
    if minimum_generation is not None and (
        isinstance(minimum_generation, bool)
        or not isinstance(minimum_generation, int)
        or not 1 <= minimum_generation <= _MAX_GENERATION
    ):
        raise NativePolicySnapshotError("native_policy_snapshot_generation_invalid")
    if lock_descriptor is None:
        with _v3_generation_lock(guard_home, deadline_monotonic=deadline_monotonic) as descriptor:
            return _v3_generation_for_policy(
                guard_home,
                policy_digest,
                deadline_monotonic=deadline_monotonic,
                force_increment=force_increment,
                minimum_generation=minimum_generation,
                lock_descriptor=descriptor,
                persist_state=persist_state,
            )
    current = _read_v3_generation_state(guard_home)
    if (
        current is not None
        and current[1] == policy_digest
        and not force_increment
        and (minimum_generation is None or current[0] >= minimum_generation)
    ):
        return current[0]
    if current is not None and current[0] == _MAX_GENERATION:
        raise NativePolicySnapshotError("native_policy_snapshot_generation_exhausted")
    if minimum_generation == _MAX_GENERATION:
        raise NativePolicySnapshotError("native_policy_snapshot_generation_exhausted")
    if current is None:
        state_dir = guard_home / NATIVE_RUNTIME_STATE_DIRECTORY
        if minimum_generation is None and any(
            (state_dir / name).exists() for name in (_RUST_GENERATION_FLOOR_NAME, _RUST_SNAPSHOT_STATE_NAME)
        ):
            raise NativePolicySnapshotError("native_policy_snapshot_generation_state_missing")
        generation = max(1, (minimum_generation or 0) + 1)
    else:
        generation = max(current[0] + 1, (minimum_generation or 0) + 1)
    if persist_state:
        _write_v3_generation_state(guard_home, generation=generation, policy_digest=policy_digest)
    return generation


def _snapshot_inputs_v3(
    config: GuardConfig | Mapping[str, object],
    guard_home: Path,
    runtime_identity: str,
    rule_digest: str,
) -> tuple[dict[str, object], str, str, str, str]:
    effective_policy = effective_native_policy_v3(config)
    raw_mode = _config_value(config, "mode", "prompt")
    if not isinstance(raw_mode, str) or raw_mode not in _VALID_INPUT_MODES:
        raise NativePolicySnapshotError("native_policy_snapshot_mode_invalid")
    mode = "observe" if raw_mode == "observe" or effective_policy["protection_posture"] == "watch" else "enforce"
    scope_digest = _scope_digest_v3(guard_home)
    config_digest = _digest_v3(effective_policy)
    policy_digest = _snapshot_policy_digest_v3(
        config_digest=config_digest,
        effective_policy=effective_policy,
        mode=mode,
        rule_digest=rule_digest,
        runtime_identity=runtime_identity,
        scope_digest=scope_digest,
    )
    return effective_policy, mode, config_digest, policy_digest, scope_digest


def _snapshot_matches_inputs_v3(
    snapshot: Mapping[str, object],
    *,
    mode: str,
    config_digest: str,
    policy_digest: str,
    runtime_identity: str,
    rule_digest: str,
    scope_digest: str,
) -> bool:
    scope = snapshot.get("scope_contract")
    return (
        snapshot.get("mode") == mode
        and snapshot.get("config_digest") == config_digest
        and snapshot.get("policy_digest") == policy_digest
        and snapshot.get("runtime_identity") == runtime_identity
        and snapshot.get("rule_digest") == rule_digest
        and isinstance(scope, Mapping)
        and scope.get("scope_digest") == scope_digest
    )


def native_policy_snapshot_v3(
    *,
    config: GuardConfig | Mapping[str, object],
    guard_home: Path,
    runtime_identity: str,
    rule_digest: str,
    policy_integrity_key: bytes,
    issued_at_ms: int | None = None,
    expires_at_ms: int | None = None,
    deadline_monotonic: float | None = None,
    renew_after_generation: int | None = None,
) -> dict[str, object]:
    """Build or reuse one generation-bound snapshot and provision its key.

    The cache and generation state are protected by the same owner-private
    lock. This makes a signed generation durable before IPC begins and keeps
    concurrent publishers from rebuilding different bytes for one generation.
    ``renew_after_generation`` requests a strictly newer generation while
    allowing retries to reuse a previously materialized renewal candidate.
    """

    verifier_key: bytes | None = None
    try:
        if renew_after_generation is not None and (
            isinstance(renew_after_generation, bool)
            or not isinstance(renew_after_generation, int)
            or renew_after_generation <= 0
        ):
            raise NativePolicySnapshotError("native_policy_snapshot_generation_invalid")
        if not _valid_digest_v3(runtime_identity) or not _valid_digest_v3(rule_digest):
            raise NativePolicySnapshotError("native_policy_snapshot_identity_invalid")
        requested_issued_at_ms = int(time.time() * 1_000) if issued_at_ms is None else issued_at_ms
        if not _valid_u64_v3(requested_issued_at_ms):
            raise NativePolicySnapshotError("native_policy_snapshot_expiry_invalid")
        requested_expires_at_ms = (
            requested_issued_at_ms + POLICY_SNAPSHOT_MAX_EXPIRY_MS if expires_at_ms is None else expires_at_ms
        )
        if (
            not _valid_u64_v3(requested_expires_at_ms)
            or requested_expires_at_ms <= requested_issued_at_ms
            or requested_expires_at_ms - requested_issued_at_ms > POLICY_SNAPSHOT_MAX_EXPIRY_MS
        ):
            raise NativePolicySnapshotError("native_policy_snapshot_expiry_invalid")
        verifier_key = derive_native_policy_verifier_key(policy_integrity_key)
        provision_native_policy_verifier_key(guard_home, policy_integrity_key)
        effective_policy, mode, config_digest, policy_digest, scope_digest = _snapshot_inputs_v3(
            config,
            guard_home,
            runtime_identity,
            rule_digest,
        )
        current_time_ms = int(time.time() * 1_000)
        with _v3_generation_lock(guard_home, deadline_monotonic=deadline_monotonic) as lock_descriptor:
            _recover_v3_snapshot_transaction(guard_home, verifier_key)
            cached = _read_v3_snapshot_cache(guard_home, verifier_key=verifier_key)
            current = _read_v3_generation_state(guard_home)
            cache_matches = False
            cache_generation: int | None = None
            if cached is not None:
                cached_snapshot, _cached_bytes = cached
                cache_matches = _snapshot_matches_inputs_v3(
                    cached_snapshot,
                    mode=mode,
                    config_digest=config_digest,
                    policy_digest=policy_digest,
                    runtime_identity=runtime_identity,
                    rule_digest=rule_digest,
                    scope_digest=scope_digest,
                )
                cache_generation_value = cached_snapshot.get("generation")
                if not cache_matches or not isinstance(cache_generation_value, int):
                    cache_generation = None
                else:
                    cache_generation = cache_generation_value
            if cache_matches:
                assert cached is not None and cache_generation is not None
                if current is None or current != (cache_generation, policy_digest):
                    raise NativePolicySnapshotError("native_policy_snapshot_generation_state_invalid")
                cache_expires = cached[0].get("expires_at_ms")
                cache_is_current = isinstance(cache_expires, int) and cache_expires > current_time_ms
                if cache_is_current and (renew_after_generation is None or cache_generation > renew_after_generation):
                    return cached[0]
                if not cache_is_current:
                    renew_after_generation = max(renew_after_generation or 0, cache_generation)
            if current is not None and current[1] == policy_digest:
                if renew_after_generation is None:
                    # A state record without its exact signed bytes cannot be
                    # safely reconstructed after a crash.
                    raise NativePolicySnapshotError("native_policy_snapshot_cache_missing")
                if current[0] > renew_after_generation:
                    raise NativePolicySnapshotError("native_policy_snapshot_cache_missing")
                generation = _v3_generation_for_policy(
                    guard_home,
                    policy_digest,
                    deadline_monotonic=deadline_monotonic,
                    force_increment=True,
                    minimum_generation=renew_after_generation,
                    lock_descriptor=lock_descriptor,
                    persist_state=False,
                )
            else:
                generation = _v3_generation_for_policy(
                    guard_home,
                    policy_digest,
                    deadline_monotonic=deadline_monotonic,
                    minimum_generation=renew_after_generation,
                    lock_descriptor=lock_descriptor,
                    persist_state=False,
                )
            snapshot = build_policy_snapshot_v3(
                config={**effective_policy, "mode": mode},
                guard_home=guard_home,
                runtime_identity=runtime_identity,
                rule_digest=rule_digest,
                verifier_key=verifier_key,
                generation=generation,
                issued_at_ms=issued_at_ms,
                expires_at_ms=expires_at_ms,
            )
            _write_v3_snapshot_file(
                guard_home,
                _NATIVE_POLICY_SNAPSHOT_PENDING_NAME,
                snapshot,
            )
            _write_v3_snapshot_cache(guard_home, snapshot)
            _write_v3_generation_state(
                guard_home,
                generation=generation,
                policy_digest=policy_digest,
            )
            _clear_v3_snapshot_pending(guard_home)
            return snapshot
    finally:
        # The caller's master is an ephemeral input. Clear both local
        # references on every success and failure path; snapshots contain
        # only the purpose-specific verifier-derived key id and MAC.
        verifier_key = None
        policy_integrity_key = b""


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


def _stricter_action(left: object, right: object) -> str:
    if not isinstance(left, str) or left not in _ACTION_SEVERITY:
        raise NativePolicySnapshotError("native_policy_snapshot_policy_invalid")
    if not isinstance(right, str) or right not in _ACTION_SEVERITY:
        raise NativePolicySnapshotError("native_policy_snapshot_policy_invalid")
    return left if _ACTION_SEVERITY[left] >= _ACTION_SEVERITY[right] else right


def _merge_effective_native_policies(
    policies: tuple[Mapping[str, object], ...],
) -> dict[str, object]:
    """Compile home, workspace, and managed overlays into one native policy.

    A resident has one authenticated snapshot per Guard home. When more than
    one workspace is observed, composing selector maps by the lattice maximum
    gives every workspace the strongest effective floor without placing a raw
    workspace path or a Python decision in the native request. MDM overlays
    are already applied by ``load_guard_config`` before this compiler runs.
    """

    if not policies:
        raise NativePolicySnapshotError("native_policy_snapshot_policy_invalid")
    scalar_action_fields = (
        "default_action",
        "unknown_publisher_action",
        "changed_hash_action",
        "new_network_domain_action",
        "subprocess_action",
    )
    map_fields = ("risk_actions", "harness_actions", "publisher_actions", "artifact_actions")
    merged = dict(policies[0])
    for field in scalar_action_fields:
        value = policies[0].get(field)
        for policy in policies[1:]:
            value = _stricter_action(value, policy.get(field))
        merged[field] = value
    for field in map_fields:
        values: dict[str, str] = {}
        for policy in policies:
            mapping = policy.get(field)
            if not isinstance(mapping, Mapping):
                raise NativePolicySnapshotError("native_policy_snapshot_policy_invalid")
            for key, action in mapping.items():
                if not isinstance(key, str):
                    raise NativePolicySnapshotError("native_policy_snapshot_policy_invalid")
                values[key] = _stricter_action(values.get(key, "allow"), action)
        merged[field] = values
    harness_risk_values: dict[str, dict[str, str]] = {}
    for policy in policies:
        mapping = policy.get("harness_risk_actions")
        if not isinstance(mapping, Mapping):
            raise NativePolicySnapshotError("native_policy_snapshot_policy_invalid")
        for harness, risk_actions in mapping.items():
            if not isinstance(harness, str) or not isinstance(risk_actions, Mapping):
                raise NativePolicySnapshotError("native_policy_snapshot_policy_invalid")
            target = harness_risk_values.setdefault(harness, {})
            for risk_class, action in risk_actions.items():
                if not isinstance(risk_class, str):
                    raise NativePolicySnapshotError("native_policy_snapshot_policy_invalid")
                target[risk_class] = _stricter_action(target.get(risk_class, "allow"), action)
    merged["harness_risk_actions"] = harness_risk_values
    posture_values = [policy.get("protection_posture") for policy in policies]
    if not all(isinstance(value, str) and value in _POSTURE_SEVERITY for value in posture_values):
        raise NativePolicySnapshotError("native_policy_snapshot_policy_invalid")
    posture_values = [cast(str, value) for value in posture_values]
    merged["protection_posture"] = max(posture_values, key=lambda value: _POSTURE_SEVERITY[value])
    security_values = [policy.get("security_level") for policy in policies]
    if not all(isinstance(value, str) and value in _SECURITY_LEVEL_SEVERITY for value in security_values):
        raise NativePolicySnapshotError("native_policy_snapshot_policy_invalid")
    security_values = [cast(str, value) for value in security_values]
    merged["security_level"] = max(security_values, key=lambda value: _SECURITY_LEVEL_SEVERITY[value])
    # Derive mode from the selected posture so an observe-only workspace
    # overlay cannot downgrade a protected or extra-careful home policy.
    merged["mode"] = "observe" if merged["protection_posture"] == "watch" else "enforce"
    sandbox = [policy.get("sandbox_analysis") for policy in policies]
    if not all(isinstance(value, str) and value in _SANDBOX_SEVERITY for value in sandbox):
        raise NativePolicySnapshotError("native_policy_snapshot_policy_invalid")
    sandbox = [cast(str, value) for value in sandbox]
    merged["sandbox_analysis"] = max(sandbox, key=lambda value: _SANDBOX_SEVERITY[value])
    redaction = [policy.get("receipt_redaction_level") for policy in policies]
    if not all(isinstance(value, str) and value in _REDACTION_SEVERITY for value in redaction):
        raise NativePolicySnapshotError("native_policy_snapshot_policy_invalid")
    redaction = [cast(str, value) for value in redaction]
    merged["receipt_redaction_level"] = max(redaction, key=lambda value: _REDACTION_SEVERITY[value])
    return merged


class NativePolicySnapshotPublisher:
    """Asynchronously publish an authenticated snapshot and expose its barrier."""

    def __init__(
        self,
        *,
        store: GuardStore,
        status_provider: Callable[[], Any] | None = None,
        client_request: Callable[..., bytes | None] | None = None,
        poll_interval_seconds: float = _PUBLISH_RETRY_SECONDS,
        wall_clock: Callable[[], float] | None = None,
        monotonic_clock: Callable[[], float] | None = None,
    ) -> None:
        self.store = store
        self.guard_home = Path(store.guard_home)
        self._status_provider = status_provider
        self._client_request = client_request
        self._poll_interval_seconds = max(0.05, min(5.0, poll_interval_seconds))
        self._wall_clock = wall_clock or time.time
        self._monotonic_clock = monotonic_clock or time.monotonic
        self._condition = threading.Condition()
        self._publish_event = threading.Event()
        self._closed = False
        self._started = False
        self._thread: threading.Thread | None = None
        self._snapshot: dict[str, object] | None = None
        self._acked = False
        self._epoch = 0
        self._last_error: str | None = None
        self._published_config_digest: str | None = None
        self._published_policy_fingerprint: tuple[str, str] | None = None
        self._renewal_due_monotonic: float | None = None
        self._renewal_after_generation: int | None = None
        self._retry_not_before_monotonic: float | None = None
        self._failure_count = 0
        self._workspace_paths: set[Path] = set()
        self._input_fingerprint: (
            tuple[tuple[tuple[str, tuple[int, int, int, int] | None], ...], tuple[tuple[str, int, int], ...]] | None
        ) = None
        with _PUBLISHER_LOCK:
            _PUBLISHERS.setdefault(_publisher_key(self.guard_home), set()).add(self)

    def start(self) -> None:
        with self._condition:
            if self._started or self._closed:
                return
            self._started = True
        # Provision the verifier before the first client request can start a
        # managed resident.  Publication still happens asynchronously, but a
        # shadow/diagnostic caller cannot race resident startup against key
        # creation.  Failures remain a barrier miss and are retried by the
        # publisher thread; they never become a Python semantic fallback.
        try:
            self._provision_verifier_key()
        except (NativePolicySnapshotError, OSError, RuntimeError, TypeError, ValueError) as error:
            self._record_error(str(error) or type(error).__name__)
        with self._condition:
            if self._closed:
                return
            self._thread = threading.Thread(
                target=self._run,
                name="hol-guard-native-policy-publisher",
                daemon=True,
            )
            self._thread.start()
        self.request_publish()

    def close(self, *, timeout_seconds: float = 1.0) -> None:
        with self._condition:
            if self._closed:
                return
            self._closed = True
            self._acked = False
            self._condition.notify_all()
        self._publish_event.set()
        thread = self._thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=max(0.0, timeout_seconds))
        with _PUBLISHER_LOCK:
            publishers = _PUBLISHERS.get(_publisher_key(self.guard_home))
            if publishers is not None:
                publishers.discard(self)
                if not publishers:
                    _PUBLISHERS.pop(_publisher_key(self.guard_home), None)

    def request_publish(self) -> None:
        with self._condition:
            if self._closed:
                return
            self._epoch += 1
            self._acked = False
            self._last_error = None
            self._renewal_due_monotonic = None
            self._renewal_after_generation = None
            self._retry_not_before_monotonic = None
            self._failure_count = 0
            self._condition.notify_all()
        self._publish_event.set()

    notify_policy_changed = request_publish

    def register_workspace(self, workspace: Path | None) -> bool:
        """Track workspace override files without reading them on a hook."""

        if workspace is None:
            return False
        candidate = workspace.expanduser()
        with self._condition:
            if candidate in self._workspace_paths:
                return False
            self._workspace_paths.add(candidate)
            # A newly observed workspace can add a stricter local overlay.
            # Invalidate the barrier immediately so no request can continue
            # on a home-only snapshot while the overlay is being compiled.
            self._input_fingerprint = None
        self.request_publish()
        return True

    def _provision_verifier_key(self) -> None:
        material_getter = getattr(self.store, "_policy_integrity_secret_material", None)
        if not callable(material_getter):
            raise NativePolicySnapshotError("native_policy_snapshot_integrity_key_unavailable")
        material: object = None
        master_key: bytes | None = None
        try:
            material = material_getter(create=True)
            if (
                not isinstance(material, tuple)
                or len(material) != 2
                or not isinstance(material[0], bytes)
                or not isinstance(material[1], str)
            ):
                raise NativePolicySnapshotError("native_policy_snapshot_integrity_key_unavailable")
            master_key = material[0]
            provision_native_policy_verifier_key(self.guard_home, master_key)
        finally:
            # Keep the master key only for the derivation call.  The derived
            # verifier is the only value written to native runtime state.
            master_key = None
            material = None

    def _mark_expired_locked(self) -> None:
        snapshot = self._snapshot
        if not self._acked or snapshot is None:
            return
        expires_at_ms = snapshot.get("expires_at_ms")
        if not isinstance(expires_at_ms, int) or expires_at_ms > int(self._wall_clock() * 1_000):
            return
        generation = snapshot.get("generation")
        self._acked = False
        self._last_error = "native_policy_snapshot_expired"
        self._renewal_due_monotonic = None
        self._renewal_after_generation = generation if isinstance(generation, int) and generation > 0 else None
        self._retry_not_before_monotonic = self._monotonic_clock()
        self._condition.notify_all()
        self._publish_event.set()

    @staticmethod
    def _renewal_jitter_seconds(snapshot: Mapping[str, object], remaining_seconds: float) -> float:
        digest = snapshot.get("policy_digest")
        generation = snapshot.get("generation")
        if not isinstance(digest, str) or not isinstance(generation, int) or remaining_seconds <= 0:
            return 0.0
        seed = hashlib.sha256(f"{generation}:{digest}".encode("ascii")).digest()
        fraction = int.from_bytes(seed[:4], "big") / float(1 << 32)
        return min(_RENEWAL_JITTER_MAX_SECONDS, remaining_seconds * 0.05) * fraction

    def _schedule_renewal_locked(self, snapshot: Mapping[str, object]) -> None:
        expires_at_ms = snapshot.get("expires_at_ms")
        if not isinstance(expires_at_ms, int):
            self._renewal_due_monotonic = self._monotonic_clock()
            return
        remaining_seconds = expires_at_ms / 1_000 - self._wall_clock()
        if remaining_seconds <= 0:
            self._renewal_due_monotonic = self._monotonic_clock()
            return
        lead_seconds = min(_RENEWAL_LEAD_SECONDS, max(1.0, remaining_seconds * 0.1))
        jitter_seconds = self._renewal_jitter_seconds(snapshot, remaining_seconds)
        due_in = max(0.0, remaining_seconds - lead_seconds - jitter_seconds)
        self._renewal_due_monotonic = self._monotonic_clock() + due_in

    def is_ready(self) -> bool:
        with self._condition:
            self._mark_expired_locked()
            return self._acked and self._snapshot is not None and not self._closed

    @property
    def closed(self) -> bool:
        with self._condition:
            return self._closed

    def current_snapshot(self) -> dict[str, object] | None:
        with self._condition:
            self._mark_expired_locked()
            if not self._acked or self._snapshot is None or self._closed:
                return None
            return cast(dict[str, object], json.loads(json.dumps(self._snapshot)))

    def current_snapshot_binding(self) -> dict[str, object] | None:
        """Return the small immutable request binding for the hot hook path.

        The resident owns the authenticated full snapshot after publication.
        Hook requests only need the values that bind them to that resident
        snapshot; avoid serializing and copying policy rules on every hook.
        """
        with self._condition:
            self._mark_expired_locked()
            if not self._acked or self._snapshot is None or self._closed:
                return None
            snapshot = self._snapshot
            return {
                "generation": snapshot.get("generation"),
                "policy_digest": snapshot.get("policy_digest"),
                "runtime_identity": snapshot.get("runtime_identity"),
                "mode": snapshot.get("mode"),
            }

    @property
    def last_error(self) -> str | None:
        with self._condition:
            return self._last_error

    def wait_until_ready(self, deadline_monotonic: float | None = None) -> bool:
        deadline = (
            deadline_monotonic if deadline_monotonic is not None else self._monotonic_clock() + _PUBLISH_TIMEOUT_SECONDS
        )
        with self._condition:
            while not self._closed:
                self._mark_expired_locked()
                if self._acked and self._snapshot is not None:
                    return True
                remaining = deadline - self._monotonic_clock()
                if remaining <= 0:
                    break
                self._condition.wait(timeout=remaining)
            self._mark_expired_locked()
            return self._acked and self._snapshot is not None and not self._closed

    def _run(self) -> None:
        while True:
            with self._condition:
                if self._closed:
                    return
                self._mark_expired_locked()
            fingerprint = self._current_input_fingerprint()
            if self._input_fingerprint is None:
                self._input_fingerprint = fingerprint
            elif fingerprint[1] != self._input_fingerprint[1]:
                # Resident generation files are created on every managed
                # restart. Re-push the last snapshot before a hook can rely
                # on the replacement resident's in-memory policy.
                self._input_fingerprint = fingerprint
                self.request_publish()
            elif fingerprint[0] != self._input_fingerprint[0]:
                previous_inputs = dict(self._input_fingerprint[0])
                current_inputs = dict(fingerprint[0])
                changed_paths = {
                    path
                    for path in previous_inputs.keys() | current_inputs.keys()
                    if previous_inputs.get(path) != current_inputs.get(path)
                }
                self._input_fingerprint = fingerprint
                if self._policy_input_changed(changed_paths):
                    self.request_publish()
            with self._condition:
                if self._closed:
                    return
                self._mark_expired_locked()
                now = self._monotonic_clock()
                wait_seconds = self._poll_interval_seconds
                if self._retry_not_before_monotonic is not None:
                    wait_seconds = min(
                        wait_seconds,
                        max(0.0, self._retry_not_before_monotonic - now),
                    )
                if self._acked and self._renewal_due_monotonic is not None:
                    wait_seconds = min(
                        wait_seconds,
                        max(0.0, self._renewal_due_monotonic - now),
                    )
            self._publish_event.wait(timeout=wait_seconds)
            self._publish_event.clear()
            with self._condition:
                if self._closed:
                    return
                self._mark_expired_locked()
                now = self._monotonic_clock()
                if self._acked and self._renewal_due_monotonic is not None and now >= self._renewal_due_monotonic:
                    snapshot = self._snapshot
                    generation = snapshot.get("generation") if snapshot is not None else None
                    self._acked = False
                    self._last_error = None
                    self._renewal_due_monotonic = None
                    self._renewal_after_generation = (
                        generation if isinstance(generation, int) and generation > 0 else None
                    )
                    self._retry_not_before_monotonic = now
                    self._failure_count = 0
                should_publish = (
                    not self._closed
                    and not self._acked
                    and (self._retry_not_before_monotonic is None or now >= self._retry_not_before_monotonic)
                )
                renewal_after_generation = self._renewal_after_generation
            if should_publish:
                self._publish_once(renew_after_generation=renewal_after_generation)

    def _current_input_fingerprint(
        self,
    ) -> tuple[tuple[tuple[str, tuple[int, int, int, int] | None], ...], tuple[tuple[str, int, int], ...]]:
        values: list[tuple[str, tuple[int, int, int, int] | None]] = []
        # The database and both journal modes are watched for cross-process
        # changes. WAL-only writes are included because they can contain an
        # effective policy mutation before checkpointing.
        paths = (
            self.guard_home / "config.toml",
            self.guard_home / "guard.db",
            self.guard_home / "guard.db-wal",
            self.guard_home / "guard.db-shm",
            self.guard_home / "guard.db-journal",
            self.guard_home / NATIVE_RUNTIME_STATE_DIRECTORY / NATIVE_POLICY_VERIFIER_KEY_NAME,
            *self._external_policy_paths(),
            *self._workspace_policy_paths(),
        )
        seen_paths: set[str] = set()
        for path in paths:
            path_key = str(path)
            if path_key in seen_paths:
                continue
            seen_paths.add(path_key)
            try:
                metadata = path.stat()
            except OSError:
                values.append((path_key, None))
            else:
                values.append(
                    (
                        path_key,
                        (metadata.st_mtime_ns, metadata.st_size, metadata.st_ino, metadata.st_ctime_ns),
                    )
                )
        resident_values: list[tuple[str, int, int]] = []
        state_dir = self.guard_home / NATIVE_RUNTIME_STATE_DIRECTORY
        try:
            resident_directories = sorted(
                (entry for entry in state_dir.iterdir() if entry.name.startswith("resident-v3-")),
                key=lambda entry: entry.name,
            )
        except OSError:
            resident_directories = []
        for directory in resident_directories:
            try:
                metadata = directory.stat()
            except OSError:
                continue
            resident_values.append((directory.name, metadata.st_mtime_ns, metadata.st_size))
            try:
                generation_files = sorted(
                    (entry for entry in directory.iterdir() if entry.name.startswith("generation-")),
                    key=lambda entry: entry.name,
                )
            except OSError:
                generation_files = []
            for entry in generation_files:
                try:
                    metadata = entry.stat()
                except OSError:
                    continue
                resident_values.append((f"{directory.name}/{entry.name}", metadata.st_mtime_ns, metadata.st_size))
        return tuple(values), tuple(resident_values)

    def _workspace_policy_paths(self) -> tuple[Path, ...]:
        with self._condition:
            workspaces = tuple(self._workspace_paths)
        paths: list[Path] = []
        for workspace in workspaces:
            paths.extend(workspace / filename for filename in (".ai-plugin-scanner-guard.toml", ".hol-guard.toml"))
        return tuple(paths)

    def _compiled_effective_policy(self) -> dict[str, object]:
        """Build the native snapshot input off the synchronous hook path."""

        from .config import load_guard_config

        with self._condition:
            workspaces = tuple(sorted(self._workspace_paths, key=str))
        configs = [load_guard_config(self.guard_home)]
        configs.extend(load_guard_config(self.guard_home, workspace=workspace) for workspace in workspaces)
        return _merge_effective_native_policies(
            tuple(effective_native_policy_v3(config) | {"mode": config.mode} for config in configs)
        )

    @staticmethod
    def _external_policy_paths() -> tuple[Path, ...]:
        try:
            from .mdm.contracts import default_machine_paths

            machine_paths = default_machine_paths()
        except (OSError, RuntimeError, ValueError):
            return ()
        paths = [machine_paths.policy_path]
        paths.append(machine_paths.state_root / "managed-policy-cache.json")
        return tuple(path for path in paths if path is not None)

    def _policy_input_changed(self, changed_paths: set[str] | None = None) -> bool:
        """Compare effective policy in the publisher thread, never in hooks."""

        if changed_paths:
            config_path = str(self.guard_home / "config.toml")
            database_paths = {
                str(self.guard_home / name) for name in ("guard.db", "guard.db-wal", "guard.db-shm", "guard.db-journal")
            }
            if any(path != config_path and path in database_paths for path in changed_paths):
                return True
            if any(path != config_path for path in changed_paths):
                # Workspace overrides, MDM policy files, and verifier state
                # are all effective-input boundaries. Republish before the
                # resident is used even when this Python projection cannot
                # yet express a workspace-specific native policy.
                return True
        try:
            effective_policy = self._compiled_effective_policy()
            current_fingerprint = (
                cast(str, _digest_v3(effective_policy)),
                cast(str, effective_policy["mode"]),
            )
        except (OSError, NativePolicySnapshotError, TypeError, ValueError, RuntimeError):
            return True
        return self._published_policy_fingerprint != current_fingerprint

    def _record_error(self, error: str) -> None:
        safe = error.strip().lower()
        if not safe or len(safe) > 128 or not all(character.isalnum() or character in "_-" for character in safe):
            safe = "native_policy_snapshot_publish_failed"
        with self._condition:
            self._last_error = safe
            self._acked = False
            self._failure_count += 1
            delay = min(
                _PUBLISH_RETRY_MAX_SECONDS,
                self._poll_interval_seconds * (2 ** min(self._failure_count - 1, 5)),
            )
            retry_seed = hashlib.sha256(f"{self._failure_count}:{safe}".encode("ascii")).digest()
            retry_fraction = int.from_bytes(retry_seed[:2], "big") / float(1 << 16)
            self._retry_not_before_monotonic = (
                self._monotonic_clock()
                + delay
                + min(
                    0.1,
                    self._poll_interval_seconds * 0.25,
                )
                * retry_fraction
            )
            self._condition.notify_all()

    def _publish_once(self, *, renew_after_generation: int | None = None) -> None:
        with self._condition:
            if self._closed:
                return
            if renew_after_generation is None:
                renew_after_generation = self._renewal_after_generation
            publish_epoch = self._epoch
        try:
            status_provider = self._status_provider
            if status_provider is None:
                from .native_runtime import native_runtime_status

                status_provider = native_runtime_status
            status = status_provider()
            if getattr(status, "mode", None) not in {"auto", "force", "shadow"}:
                self._record_error("native_policy_snapshot_native_disabled")
                return
            identity = getattr(status, "identity", None)
            capabilities = getattr(status, "capabilities", None)
            if (
                not getattr(status, "available", False)
                or not getattr(status, "compatible", False)
                or identity is None
                or capabilities is None
            ):
                self._record_error("native_policy_snapshot_runtime_unavailable")
                return
            features = getattr(capabilities, "features", ())
            if set(features) < _REQUIRED_PUBLISH_FEATURES:
                self._record_error("native_policy_snapshot_protocol_unsupported")
                return
            material_getter = getattr(self.store, "_policy_integrity_secret_material", None)
            if not callable(material_getter):
                self._record_error("native_policy_snapshot_integrity_key_unavailable")
                return
            material: object = None
            master_key: bytes | None = None
            try:
                material = material_getter(create=True)
                if (
                    not isinstance(material, tuple)
                    or len(material) != 2
                    or not isinstance(material[0], bytes)
                    or not isinstance(material[1], str)
                ):
                    self._record_error("native_policy_snapshot_integrity_key_unavailable")
                    return
                master_key = material[0]
                config = self._compiled_effective_policy()
                client = self._client_request
                if client is None:
                    from .native_resident_client import native_resident_client_request

                    client = native_resident_client_request
                from .native_runtime import _isolated_environment

                # A trusted resident may retain only its monotonic floor after
                # restart/corruption recovery.  In that state it returns a
                # typed ACK, never an error string that could be spoofed or
                # confused with a transport failure.  Bound recovery to one
                # in-flight retry; subsequent publisher iterations reuse the
                # materialized candidate from the immutable cache.
                recovery_attempted = False
                while True:
                    snapshot = native_policy_snapshot_v3(
                        config=config,
                        guard_home=self.guard_home,
                        runtime_identity=identity.sha256,
                        rule_digest=capabilities.rule_digest,
                        policy_integrity_key=master_key,
                        issued_at_ms=int(self._wall_clock() * 1_000),
                        deadline_monotonic=self._monotonic_clock() + _PUBLISH_TIMEOUT_SECONDS,
                        renew_after_generation=renew_after_generation,
                    )
                    try:
                        encoded = _policy_snapshot_push_bytes_v3(snapshot)
                    except NativePolicySnapshotError as error:
                        self._record_error(str(error))
                        return
                    output = client(
                        executable=identity.path,
                        guard_home=self.guard_home,
                        environment=_isolated_environment(),
                        payload=encoded,
                        deadline_monotonic=time.monotonic() + _PUBLISH_TIMEOUT_SECONDS,
                    )
                    ack = self._decode_ack(output)
                    if ack is None:
                        self._record_error("native_policy_snapshot_ack_invalid")
                        return
                    if ack["status"] == POLICY_SNAPSHOT_ACK_REQUIRES_NEW_GENERATION:
                        floor = ack["generation"]
                        candidate_generation = snapshot["generation"]
                        if (
                            recovery_attempted
                            or isinstance(floor, bool)
                            or not isinstance(floor, int)
                            or not isinstance(candidate_generation, int)
                            or floor < candidate_generation
                        ):
                            self._record_error("native_policy_snapshot_ack_mismatch")
                            return
                        renew_after_generation = floor
                        recovery_attempted = True
                        continue
                    if ack["generation"] != snapshot["generation"] or ack["policy_digest"] != snapshot["policy_digest"]:
                        self._record_error("native_policy_snapshot_ack_mismatch")
                        return
                    break
            finally:
                # The master is only an ephemeral input to derivation/signing;
                # never retain it in publisher state or an exception context.
                master_key = None
                material = None
            with self._condition:
                # A mutation may have invalidated the barrier while this
                # request was in flight. Do not let an older ACK make that
                # newer policy appear ready.
                if self._closed or self._epoch != publish_epoch:
                    return
                self._snapshot = snapshot
                self._published_config_digest = cast(str, snapshot["config_digest"])
                self._published_policy_fingerprint = (
                    cast(str, snapshot["config_digest"]),
                    cast(str, snapshot["mode"]),
                )
                self._acked = True
                self._last_error = None
                self._renewal_after_generation = None
                self._failure_count = 0
                self._retry_not_before_monotonic = None
                self._schedule_renewal_locked(snapshot)
                self._condition.notify_all()
        except NativePolicySnapshotError as error:
            self._record_error(str(error))
        except (OSError, RuntimeError, TypeError, ValueError, AttributeError) as error:
            self._record_error(type(error).__name__)

    @staticmethod
    def _decode_ack(output: bytes | None) -> dict[str, object] | None:
        if output is None or len(output) == 0 or len(output) > _MAX_ACK_BYTES:
            return None
        try:
            value = _strict_json_loads_v3(output)
        except NativePolicySnapshotError:
            return None
        if not isinstance(value, dict) or set(value) != {"status", "generation", "policy_digest", "idempotent"}:
            return None
        status = value.get("status")
        if not isinstance(status, str) or status not in {"accepted", POLICY_SNAPSHOT_ACK_REQUIRES_NEW_GENERATION}:
            return None
        if (
            isinstance(value.get("generation"), bool)
            or not isinstance(value.get("generation"), int)
            or value.get("generation", 0) <= 0
            or not _valid_digest_v3(value.get("policy_digest"))
            or not isinstance(value.get("idempotent"), bool)
        ):
            return None
        if status == POLICY_SNAPSHOT_ACK_REQUIRES_NEW_GENERATION and value.get("idempotent") is not False:
            return None
        return value


def get_native_policy_snapshot_publisher(store: GuardStore) -> NativePolicySnapshotPublisher:
    """Return the per-Guard-home publisher shared by daemon hook workers."""

    key = _publisher_key(Path(store.guard_home))
    with _PUBLISHER_LOCK:
        for publisher in _PUBLISHERS.get(key, ()):
            if not publisher.closed:
                return publisher
        return NativePolicySnapshotPublisher(store=store)


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
