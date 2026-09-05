"""Generation allocation and snapshot materialization."""

from __future__ import annotations

import time
from collections.abc import Mapping
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .native_policy_snapshot_codec import _digest_v3, _valid_digest_v3, derive_native_policy_verifier_key
from .native_policy_snapshot_constants import (
    _MAX_GENERATION,
    _NATIVE_POLICY_SNAPSHOT_PENDING_NAME,
    _RUST_GENERATION_FLOOR_NAME,
    _RUST_SNAPSHOT_STATE_NAME,
    _VALID_INPUT_MODES,
    NATIVE_RUNTIME_STATE_DIRECTORY,
    POLICY_SNAPSHOT_MAX_EXPIRY_MS,
    NativePolicySnapshotError,
)
from .native_policy_snapshot_contract import (
    _snapshot_policy_digest_v3,
    _valid_u64_v3,
    effective_native_policy_v3,
)
from .native_policy_snapshot_policy import _config_value, _scope_digest_v3
from .native_policy_snapshot_storage import (
    _read_v3_generation_state,
    _v3_generation_lock,
    _write_v3_generation_state,
)
from .native_policy_snapshot_windows_key import provision_native_policy_verifier_key

if TYPE_CHECKING:
    from .config import GuardConfig


def _snapshot_api() -> Any:
    """Resolve façade hooks lazily to preserve compatibility monkeypatches."""

    from . import native_policy_snapshot

    return native_policy_snapshot


def _private_guard_home(guard_home: Path) -> None:
    """Use the façade's established owner/private-home validation seam."""

    from . import native_policy_snapshot

    native_policy_snapshot._private_guard_home(guard_home)


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


def _validate_snapshot_request_v3(
    runtime_identity: str,
    rule_digest: str,
    issued_at_ms: int | None,
    expires_at_ms: int | None,
    renew_after_generation: int | None,
) -> None:
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


def _cached_snapshot_v3(
    api: Any,
    guard_home: Path,
    verifier_key: bytes,
    current: tuple[int, str] | None,
    *,
    mode: str,
    config_digest: str,
    policy_digest: str,
    runtime_identity: str,
    rule_digest: str,
    scope_digest: str,
    renew_after_generation: int | None,
) -> tuple[dict[str, object] | None, int | None]:
    cached = api._read_v3_snapshot_cache(guard_home, verifier_key=verifier_key)
    if cached is None:
        return None, renew_after_generation
    cached_snapshot, _cached_bytes = cached
    matches = _snapshot_matches_inputs_v3(
        cached_snapshot,
        mode=mode,
        config_digest=config_digest,
        policy_digest=policy_digest,
        runtime_identity=runtime_identity,
        rule_digest=rule_digest,
        scope_digest=scope_digest,
    )
    cache_generation = cached_snapshot.get("generation")
    if not matches or not isinstance(cache_generation, int):
        return None, renew_after_generation
    if current is None or current != (cache_generation, policy_digest):
        raise NativePolicySnapshotError("native_policy_snapshot_generation_state_invalid")
    current_time_ms = int(time.time() * 1_000)
    expires = cached_snapshot.get("expires_at_ms")
    cache_is_current = isinstance(expires, int) and expires > current_time_ms
    if cache_is_current and (renew_after_generation is None or cache_generation > renew_after_generation):
        return cached_snapshot, renew_after_generation
    if not cache_is_current:
        renew_after_generation = max(renew_after_generation or 0, cache_generation)
    return None, renew_after_generation


def _next_snapshot_generation_v3(
    api: Any,
    guard_home: Path,
    policy_digest: str,
    *,
    deadline_monotonic: float | None,
    renew_after_generation: int | None,
    current: tuple[int, str] | None,
    lock_descriptor: int,
) -> int:
    if current is not None and current[1] == policy_digest:
        if renew_after_generation is None or current[0] > renew_after_generation:
            raise NativePolicySnapshotError("native_policy_snapshot_cache_missing")
        return api._v3_generation_for_policy(
            guard_home,
            policy_digest,
            deadline_monotonic=deadline_monotonic,
            force_increment=True,
            minimum_generation=renew_after_generation,
            lock_descriptor=lock_descriptor,
            persist_state=False,
        )
    return api._v3_generation_for_policy(
        guard_home,
        policy_digest,
        deadline_monotonic=deadline_monotonic,
        minimum_generation=renew_after_generation,
        lock_descriptor=lock_descriptor,
        persist_state=False,
    )


def _materialize_snapshot_v3(
    api: Any,
    *,
    guard_home: Path,
    effective_policy: Mapping[str, object],
    mode: str,
    runtime_identity: str,
    rule_digest: str,
    verifier_key: bytes,
    generation: int,
    issued_at_ms: int | None,
    expires_at_ms: int | None,
    policy_digest: str,
) -> dict[str, object]:
    snapshot = api.build_policy_snapshot_v3(
        config={**effective_policy, "mode": mode},
        guard_home=guard_home,
        runtime_identity=runtime_identity,
        rule_digest=rule_digest,
        verifier_key=verifier_key,
        generation=generation,
        issued_at_ms=issued_at_ms,
        expires_at_ms=expires_at_ms,
    )
    api._write_v3_snapshot_file(guard_home, _NATIVE_POLICY_SNAPSHOT_PENDING_NAME, snapshot)
    api._write_v3_snapshot_cache(guard_home, snapshot)
    api._write_v3_generation_state(
        guard_home,
        generation=generation,
        policy_digest=policy_digest,
    )
    api._clear_v3_snapshot_pending(guard_home)
    return snapshot


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
        _validate_snapshot_request_v3(
            runtime_identity,
            rule_digest,
            issued_at_ms,
            expires_at_ms,
            renew_after_generation,
        )
        verifier_key = derive_native_policy_verifier_key(policy_integrity_key)
        provision_native_policy_verifier_key(guard_home, policy_integrity_key)
        effective_policy, mode, config_digest, policy_digest, scope_digest = _snapshot_inputs_v3(
            config,
            guard_home,
            runtime_identity,
            rule_digest,
        )
        api = _snapshot_api()
        with api._v3_generation_lock(guard_home, deadline_monotonic=deadline_monotonic) as lock_descriptor:
            api._recover_v3_snapshot_transaction(guard_home, verifier_key)
            current = api._read_v3_generation_state(guard_home)
            cached_snapshot, renew_after_generation = _cached_snapshot_v3(
                api,
                guard_home,
                verifier_key,
                current,
                mode=mode,
                config_digest=config_digest,
                policy_digest=policy_digest,
                runtime_identity=runtime_identity,
                rule_digest=rule_digest,
                scope_digest=scope_digest,
                renew_after_generation=renew_after_generation,
            )
            if cached_snapshot is not None:
                return cached_snapshot
            generation = _next_snapshot_generation_v3(
                api,
                guard_home,
                policy_digest,
                deadline_monotonic=deadline_monotonic,
                renew_after_generation=renew_after_generation,
                current=current,
                lock_descriptor=lock_descriptor,
            )
            return _materialize_snapshot_v3(
                api,
                guard_home=guard_home,
                effective_policy=effective_policy,
                mode=mode,
                runtime_identity=runtime_identity,
                rule_digest=rule_digest,
                verifier_key=verifier_key,
                generation=generation,
                policy_digest=policy_digest,
                issued_at_ms=issued_at_ms,
                expires_at_ms=expires_at_ms,
            )
    finally:
        # The caller's master is an ephemeral input. Clear both local
        # references on every success and failure path; snapshots contain
        # only the purpose-specific verifier-derived key id and MAC.
        verifier_key = None
        policy_integrity_key = b""
