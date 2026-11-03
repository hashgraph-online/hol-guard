"""Platform-managed policy, loaded and parsed by the native runtime.

Rust reads the machine authority (the administrator-owned profile, its cache or
the Windows registry), parses the document strictly and writes the state back.
This module only frames that request, keeps a stat-validated memo so an
unchanged machine is not reread, and builds the contract dataclasses.
"""

from __future__ import annotations

import os
import platform
import threading
import time
from collections.abc import Mapping
from pathlib import Path
from typing import Any, cast

from .contracts import (
    MDM_POLICY_SCHEMA_VERSION,
    ManagedIntegrityTrust,
    ManagedNetworkPolicy,
    ManagedPolicy,
    ManagedPolicyState,
    ManagedUpdatePolicy,
    canonical_payload_hash,
    default_machine_paths,
)
from .runtime_request import runtime_answer

MANAGED_POLICY_LOAD_COMMAND = "managed-policy-load"
MANAGED_POLICY_LOAD_FEATURE = "native-managed-policy-load-v1"
MANAGED_POLICY_LOAD_SCHEMA = "managed-policy-load.v1"
_TIMEOUT_SECONDS = 10.0
# A policy document is bounded at 1 MiB, so its parsed form fits well inside.
_OUTPUT_LIMIT_BYTES = 4 * 1024 * 1024
_WINDOWS_POLICY_KEY = r"Software\Policies\HOL\Guard"
_WINDOWS_POLICY_SOURCE = r"HKLM\Software\Policies\HOL\Guard"
# A file modified this recently may still change within one timestamp tick, so
# its state is neither stored nor reused.
_RACY_WINDOW_NS = 2_000_000_000
_MEMO_LIMIT = 8
_MEMO: dict[tuple[object, ...], ManagedPolicyState] = {}
_MEMO_LOCK = threading.Lock()


class ManagedPolicyError(ValueError):
    """A managed policy failed strict validation."""


class _NativeUnavailableError(Exception):
    pass


def _call_native(request: Mapping[str, object]) -> dict[str, Any]:
    response = runtime_answer(
        MANAGED_POLICY_LOAD_FEATURE,
        MANAGED_POLICY_LOAD_COMMAND,
        {"schema": MANAGED_POLICY_LOAD_SCHEMA, **request},
        deadline=time.monotonic() + _TIMEOUT_SECONDS,
        output_limit=_OUTPUT_LIMIT_BYTES,
    )
    if response is None:
        raise _NativeUnavailableError
    return cast("dict[str, Any]", response)


def _policy_from_native(raw: object) -> ManagedPolicy:
    fields = cast("dict[str, Any]", raw)
    trust = cast("dict[str, Any]", fields["integrity_trust"])
    keys = cast("dict[str, str]", trust["release_public_keys"])
    return ManagedPolicy(
        schema_version=str(fields["schema_version"]),
        settings=dict(fields["settings"]),
        locked_settings=frozenset(fields["locked_settings"]),
        required_harnesses=tuple(fields["required_harnesses"]),
        network=ManagedNetworkPolicy(**fields["network"]),
        update=ManagedUpdatePolicy(**fields["update"]),
        integrity_trust=ManagedIntegrityTrust(
            release_public_keys={key_id: bytes.fromhex(key) for key_id, key in keys.items()},
            macos_team_id=trust["macos_team_id"],
            windows_signer_thumbprints=tuple(trust["windows_signer_thumbprints"]),
        ),
        daemon_startup=fields["daemon_startup"],
        content_hash=str(fields["content_hash"]),
        policy_bundle_keyring=fields["policy_bundle_keyring"],
    )


def _state_from_native(raw: object) -> ManagedPolicyState:
    fields = cast("dict[str, Any]", raw)
    policy = fields["policy"]
    return ManagedPolicyState(
        fields["status"],
        str(fields["source"]),
        policy=_policy_from_native(policy) if policy is not None else None,
        reason_code=fields["reason_code"],
        detail=fields["detail"],
    )


def parse_managed_policy(payload: object) -> ManagedPolicy:
    """Validate one managed policy document with the runtime's own parser."""

    try:
        response = _call_native({"op": "parse", "payload": payload})
        if response.get("ok") is True:
            return _policy_from_native(response["policy"])
    except (_NativeUnavailableError, KeyError, TypeError, ValueError, AttributeError) as error:
        raise ManagedPolicyError("managed policy parser unavailable") from error
    rejected = response.get("rejected")
    raise ManagedPolicyError(rejected if isinstance(rejected, str) and rejected else "managed policy is invalid")


def _signature(path: Path) -> tuple[int, ...] | None:
    try:
        metadata = os.lstat(path)
    except FileNotFoundError:
        return None
    except (OSError, ValueError):
        return (-1,)
    return (
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_ino,
        metadata.st_dev,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _ancestor_signature(path: Path) -> tuple[int, ...] | None:
    signature = _signature(path)
    # Entries come and go in these directories, so only what the trust walk
    # reads (mode, owner and identity) may move the memo, not size or times.
    return signature[:4] if signature is not None else None


def _ancestor_signatures(path: Path) -> tuple[tuple[int, ...] | None, ...]:
    # The native trust walk refuses a file below any group- or world-writable
    # or non-root directory, so a change to one of them has to miss the memo.
    return tuple(_ancestor_signature(parent) for parent in path.parents)


def _windows_policy_key_present() -> bool:
    try:
        import winreg
    except ImportError:
        return True
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, _WINDOWS_POLICY_KEY):
            return True
    except FileNotFoundError:
        return False
    except OSError:
        return True


def _load_native(request: Mapping[str, object], source: str) -> ManagedPolicyState:
    try:
        response = _call_native(request)
        if response.get("ok") is True:
            return _state_from_native(response["state"])
    except (_NativeUnavailableError, KeyError, TypeError, ValueError, AttributeError):
        pass
    # Configured authority this process cannot read is never treated as none.
    return ManagedPolicyState("inaccessible", source, reason_code="managed_policy_native_unavailable")


def load_managed_policy(*, policy_path: Path | None = None, write_cache: bool = True) -> ManagedPolicyState:
    """Load machine authority from an explicit file or the native machine source."""

    if policy_path is not None:
        return _load_native({"op": "load", "policy_path": str(policy_path), "write_cache": False}, str(policy_path))
    system_name = platform.system()
    paths = default_machine_paths(system_name=system_name)
    cache_path = paths.state_root / "managed-policy-cache.json"
    if system_name == "Windows":
        # The registry has no cheap change signature, so a configured machine
        # is reread every time; an unconfigured one never spawns the runtime.
        if not _windows_policy_key_present() and not os.path.lexists(cache_path):
            return ManagedPolicyState("absent", _WINDOWS_POLICY_SOURCE, reason_code="managed_policy_absent")
        return _load_native({"op": "load", "write_cache": write_cache}, _WINDOWS_POLICY_SOURCE)
    if paths.policy_path is None:
        return ManagedPolicyState("absent", "native", reason_code="managed_policy_absent")
    source = str(paths.policy_path)
    signatures = (_signature(paths.policy_path), _signature(cache_path))
    if signatures == (None, None):
        return ManagedPolicyState("absent", source, reason_code="managed_policy_absent")
    key = (
        source,
        write_cache,
        *signatures,
        _ancestor_signatures(paths.policy_path),
        _ancestor_signatures(cache_path),
    )
    with _MEMO_LOCK:
        cached = _MEMO.get(key)
    if cached is not None:
        return cached
    state = _load_native({"op": "load", "write_cache": write_cache}, source)
    racy_after = time.time_ns() - _RACY_WINDOW_NS
    settled = all(
        signature is None or (len(signature) > 1 and max(signature[-2:]) < racy_after) for signature in signatures
    )
    # Only a state read from files that have not moved since is reusable. The
    # first cache write changes its signature, so that state is read once more;
    # the runtime leaves an unchanged cache in place after that.
    if settled and state.reason_code != "managed_policy_native_unavailable":
        with _MEMO_LOCK:
            _MEMO[key] = state
            while len(_MEMO) > _MEMO_LIMIT:
                del _MEMO[next(iter(_MEMO))]
    return state


def fail_closed_managed_policy() -> ManagedPolicy:
    """Return the non-weaker floor used when configured machine authority is unreadable."""

    settings: dict[str, object] = {
        "mode": "enforce",
        "security_level": "paranoid",
        "default_action": "block",
        "unknown_publisher_action": "block",
        "changed_hash_action": "block",
        "new_network_domain_action": "block",
        "subprocess_action": "block",
        "sync": False,
    }
    return ManagedPolicy(
        schema_version=MDM_POLICY_SCHEMA_VERSION,
        settings=settings,
        locked_settings=frozenset(settings),
        update=ManagedUpdatePolicy(owner="mdm", allow_downgrade=False),
        content_hash=canonical_payload_hash(
            {"schemaVersion": MDM_POLICY_SCHEMA_VERSION, "settings": settings, "failClosed": True}
        ),
    )


__all__ = [
    "ManagedPolicyError",
    "fail_closed_managed_policy",
    "load_managed_policy",
    "parse_managed_policy",
]
