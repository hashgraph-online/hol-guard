"""Provision the resident verifier key through the native runtime.

The resident refuses to serve until the owner-private derived key exists under
a guard home, so provisioning cannot be a resident call. The native runtime
owns it as a one-shot arm; this module supplies the policy master on its stdin
and reports what the runtime answered. Python never derives the key, writes it,
or compares the bytes already on disk.
"""

from __future__ import annotations

import hashlib
import json
import threading
from pathlib import Path

from .native_policy_snapshot_constants import (
    NATIVE_POLICY_VERIFIER_KEY_NAME,
    NativePolicySnapshotError,
)
from .native_policy_snapshot_windows_support import _runtime_state_directory

_PROVISION_FEATURE = "native-policy-verifier-key-provision-v1"
_PROVISION_SCHEMA = "hol-guard-native-verifier-key.v1"
_PROVISION_TIMEOUT_SECONDS = 10.0
_PROVISION_RESPONSE_LIMIT = 4096

# Provisioning is idempotent, but a policy decision lookup runs it before every
# request that needs resident authority. One process may only pay for the
# runtime launch once per guard home and master, so a success is remembered
# here. A memo entry stands for one key file and one master: it carries the
# file's identity, so a key replaced behind the memo misses it and the native
# provisioner runs again and reports the mismatch, instead of the memo
# answering for a file the runtime never looked at.
_PROVISIONED_MAX = 32
_provisioned_lock = threading.Lock()
_ProvisionEntry = tuple[str, str, tuple[int, int, int] | None]
_provisioned: dict[_ProvisionEntry, None] = {}


def _master_fingerprint(policy_integrity_key: bytes) -> str:
    """Index a remembered provisioning without holding the master itself."""

    return hashlib.blake2b(policy_integrity_key, digest_size=16).hexdigest()


def _key_identity(path: Path) -> tuple[int, int, int] | None:
    """Identify the key already on disk without reading its bytes.

    Any answer but a readable file's identity means the memo cannot stand for
    it, so an unreadable or absent key provisions again rather than being
    remembered as something the runtime has checked.
    """

    try:
        stat = path.stat()
    except OSError:
        return None
    return (stat.st_ino, stat.st_size, stat.st_mtime_ns)


def _remembered(entry: _ProvisionEntry) -> bool:
    if entry[2] is None:
        return False
    with _provisioned_lock:
        return entry in _provisioned


def _remember(entry: _ProvisionEntry) -> None:
    if entry[2] is None:
        return
    with _provisioned_lock:
        if entry in _provisioned:
            return
        if len(_provisioned) >= _PROVISIONED_MAX:
            _provisioned.pop(next(iter(_provisioned)))
        _provisioned[entry] = None


def _forget_provisioned() -> None:
    """Drop every remembered provisioning; tests call this between homes."""

    with _provisioned_lock:
        _provisioned.clear()


def _reported_code(stderr: str) -> str | None:
    """Return the error code the runtime printed, if it printed one.

    The runtime writes one code to stderr and exits non-zero. Only its shape is
    checked: the code decides between reporting tampering and degrading, and
    both the tampering set and every caller's handling live in Python, so an
    unrecognized value can only make a caller stricter.
    """

    for line in reversed(stderr.splitlines()):
        code = line.strip()
        if not 4 <= len(code) <= 80 or not code[0].islower():
            continue
        if all(c.isascii() and (c.islower() or c.isdigit() or c == "_") for c in code):
            return code
    return None


def provision_native_policy_verifier_key(
    guard_home: Path,
    policy_integrity_key: bytes,
) -> Path:
    """Provision the owner-private derived key consumed by the Rust resident.

    The runtime creates the key without ever replacing one. A changed policy
    master is therefore a safe failure requiring explicit repair rather than an
    implicit verifier reset that could invalidate the resident floor.
    """

    from .native_runtime import _run_native_process_result, native_runtime_status

    state_dir = _runtime_state_directory(guard_home)
    path = state_dir / NATIVE_POLICY_VERIFIER_KEY_NAME
    fingerprint = _master_fingerprint(policy_integrity_key)
    if _remembered((str(state_dir), fingerprint, _key_identity(path))):
        return path

    status = native_runtime_status()
    capabilities = status.capabilities
    if (
        not status.available
        or not status.compatible
        or status.identity is None
        or capabilities is None
        or _PROVISION_FEATURE not in capabilities.features
    ):
        raise NativePolicySnapshotError("native_policy_verifier_runtime_unavailable")

    result = _run_native_process_result(
        status.identity.path,
        ("provision-verifier-key", "--stdin", str(state_dir)),
        # The master never goes on argv, where another local process could
        # read it out of the process table.
        input_text=json.dumps({"policy_integrity_key": policy_integrity_key.hex()}),
        timeout_seconds=_PROVISION_TIMEOUT_SECONDS,
        output_limit=_PROVISION_RESPONSE_LIMIT,
    )
    if result.returncode != 0 or result.timed_out or result.output_limit_exceeded or result.containment_failed:
        raise NativePolicySnapshotError(_reported_code(result.stderr) or "native_policy_verifier_provision_failed")
    try:
        response = json.loads(result.stdout)
    except ValueError as error:
        raise NativePolicySnapshotError("native_policy_verifier_provision_failed") from error
    if (
        not isinstance(response, dict)
        or response.get("schema") != _PROVISION_SCHEMA
        or response.get("status") not in {"created", "verified"}
    ):
        raise NativePolicySnapshotError("native_policy_verifier_provision_failed")

    _remember((str(state_dir), fingerprint, _key_identity(path)))
    return path
