"""Generation-bound snapshot materialization through the native runtime.

The resident's ``policy-snapshot-materialize`` op owns the generation lock,
crash recovery, cache reuse, generation allocation, signing and the durable
commit. Python only gathers the effective policy and provisions the key.
"""

from __future__ import annotations

import time
from collections.abc import Mapping
from pathlib import Path
from typing import TYPE_CHECKING

from .native_command_control_binding import capture_native_command_control_binding
from .native_policy_effective import effective_native_policy_v3
from .native_policy_snapshot_codec import _valid_digest_v3, derive_native_policy_verifier_key
from .native_policy_snapshot_constants import (
    _VALID_INPUT_MODES,
    BUSINESS_NATIVE_TIMEOUT_SECONDS,
    POLICY_SNAPSHOT_MAX_EXPIRY_MS,
    NativePolicySnapshotError,
)
from .native_policy_snapshot_contract import _valid_u64_v3, snapshot_mac_matches_v3
from .native_policy_snapshot_policy import _config_value, _scope_digest_v3
from .native_policy_snapshot_windows_key import provision_native_policy_verifier_key

if TYPE_CHECKING:
    from .config import GuardConfig


def _validate_snapshot_request_v3(
    runtime_identity: str,
    rule_digest: str,
    issued_at_ms: int | None,
    expires_at_ms: int | None,
    renew_after_generation: int | None,
) -> tuple[int, int]:
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
    return requested_issued_at_ms, requested_expires_at_ms


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
    command_extensions: Mapping[str, object] | None = None,
    business_policy: Mapping[str, object] | None = None,
) -> dict[str, object]:
    """Build or reuse one generation-bound snapshot and provision its key.

    ``renew_after_generation`` requests a strictly newer generation while
    allowing retries to reuse a previously materialized renewal candidate.
    """

    from . import native_policy_snapshot
    from .native_policy_snapshot_business_bridge import (
        begin_business_deadline,
        capture_business_binding,
        end_business_deadline,
        materialize_native_snapshot,
        require_native_snapshot_runtime,
    )

    if deadline_monotonic is None:
        # One budget for a cold capability probe plus the composer and the
        # materialize exchange, so the generation lock is never waited on for
        # a fresh native budget per call.
        deadline_monotonic = time.monotonic() + 3 * BUSINESS_NATIVE_TIMEOUT_SECONDS
    deadline_token = begin_business_deadline(deadline_monotonic)
    verifier_key: bytes | None = None
    request: dict[str, object] = {}
    try:
        issued, expires = _validate_snapshot_request_v3(
            runtime_identity,
            rule_digest,
            issued_at_ms,
            expires_at_ms,
            renew_after_generation,
        )
        if business_policy is not None:
            business_policy = capture_business_binding(business_policy)
        verifier_key = derive_native_policy_verifier_key(policy_integrity_key)
        if business_policy is None:
            provision_native_policy_verifier_key(guard_home, policy_integrity_key)
        binding = capture_native_command_control_binding(command_extensions) if command_extensions is not None else None
        # Refuse on the selected resident's availability before any composer
        # spawn, so a missing consumer keeps its specific reason.
        require_native_snapshot_runtime(business=business_policy is not None)
        effective_policy = effective_native_policy_v3(config, deadline_monotonic=deadline_monotonic)
        raw_mode = _config_value(config, "mode", "prompt")
        if not isinstance(raw_mode, str) or raw_mode not in _VALID_INPUT_MODES:
            raise NativePolicySnapshotError("native_policy_snapshot_mode_invalid")
        mode = "observe" if raw_mode == "observe" or effective_policy["protection_posture"] == "watch" else "enforce"
        native_policy_snapshot._private_guard_home(guard_home)
        native_policy_snapshot._runtime_state_directory(guard_home)
        request = {
            "schema": "guard-native-policy-materialize.v1",
            "version": 1,
            "verifier_key": list(verifier_key),
            "guard_home": str(guard_home),
            "runtime_identity": runtime_identity,
            "rule_digest": rule_digest,
            "mode": mode,
            "scope_contract": {
                "schema": "guard-native-scope.v1",
                "kind": "guard-home",
                "scope_digest": _scope_digest_v3(guard_home),
                "workspace_binding": "request-source",
            },
            "effective_policy": effective_policy,
            "issued_at_ms": issued,
            "expires_at_ms": expires,
            "renew_after_generation": renew_after_generation,
        }
        if binding is not None:
            request["command_extensions"] = binding
        if business_policy is not None:
            request["business_policy"] = business_policy
        snapshot = materialize_native_snapshot(request)
        if not snapshot_mac_matches_v3(snapshot, verifier_key):
            raise NativePolicySnapshotError("native_policy_snapshot_cache_integrity_invalid")
        if business_policy is not None:
            # A business declaration provisions the resident key only once the
            # runtime has accepted its content.
            provision_native_policy_verifier_key(guard_home, policy_integrity_key)
        return snapshot
    finally:
        # The caller's master is an ephemeral input. Clear both local
        # references on every success and failure path; snapshots contain
        # only the purpose-specific verifier-derived key id and MAC.
        # CPython's JSON/subprocess copies cannot be wiped; drop owned
        # references only.
        key = request.pop("verifier_key", None)
        if isinstance(key, list):
            key.clear()
        verifier_key = None
        policy_integrity_key = b""
        end_business_deadline(deadline_token)
