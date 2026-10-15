"""Policy snapshot v3 construction request, MAC re-check, and bounded encoding.

The Rust resident owns content validation and digests; this module only builds
the constructor request and verifies the returned MAC."""

from __future__ import annotations

import hashlib
import hmac
import time
from collections.abc import Mapping
from pathlib import Path
from typing import TYPE_CHECKING, cast

from .native_command_control_binding import capture_native_command_control_binding
from .native_policy_effective import effective_native_policy_v3
from .native_policy_snapshot_codec import (
    _canonical_json_bytes_v3,
    _validate_json_limits_v3,
    native_policy_verifier_key_id,
)
from .native_policy_snapshot_constants import (
    _MAX_U64,
    _PUBLISH_TIMEOUT_SECONDS,
    _VALID_INPUT_MODES,
    _VERIFIER_KEY_BYTES,
    POLICY_SNAPSHOT_INTEGRITY_DOMAIN,
    POLICY_SNAPSHOT_MAX_BYTES,
    POLICY_SNAPSHOT_MAX_EXPIRY_MS,
    POLICY_SNAPSHOT_PUSH_SCHEMA,
    NativePolicySnapshotError,
)
from .native_policy_snapshot_policy import _config_value, _scope_digest_v3

if TYPE_CHECKING:
    from .config import GuardConfig


_INTEGRITY_ALGORITHM_V3 = "hmac-sha256"
_INTEGRITY_FIELDS_V3 = frozenset({"algorithm", "key_id", "mac"})


def _valid_u64_v3(value: object) -> bool:
    return type(value) is int and 0 <= value <= _MAX_U64


def _valid_digest_v3(value: object) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(character in "0123456789abcdef" for character in value)


def _snapshot_integrity_mac_v3(snapshot: Mapping[str, object], verifier_key: bytes) -> str:
    """Recompute the snapshot MAC; content validation belongs to the resident."""

    signing_value = dict(snapshot)
    signing_value.pop("integrity", None)
    return hmac.new(
        verifier_key,
        POLICY_SNAPSHOT_INTEGRITY_DOMAIN + _canonical_json_bytes_v3(signing_value),
        hashlib.sha256,
    ).hexdigest()


def snapshot_mac_matches_v3(snapshot: Mapping[str, object], verifier_key: bytes) -> bool:
    """Constant-time MAC check that fails closed on any malformed integrity block."""

    integrity = snapshot.get("integrity")
    if not isinstance(integrity, Mapping) or set(integrity) != _INTEGRITY_FIELDS_V3:
        return False
    mac = integrity.get("mac")
    if (
        integrity.get("algorithm") != _INTEGRITY_ALGORITHM_V3
        or integrity.get("key_id") != native_policy_verifier_key_id(verifier_key)
        or not _valid_digest_v3(mac)
    ):
        return False
    return hmac.compare_digest(
        cast(str, mac).encode("ascii"), _snapshot_integrity_mac_v3(snapshot, verifier_key).encode()
    )


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
    command_extensions: Mapping[str, object] | None = None,
    business_policy: Mapping[str, object] | None = None,
    deadline_monotonic: float | None = None,
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
    from .native_policy_snapshot_business_bridge import require_native_snapshot_runtime

    # Select the resident (keeping its specific refusal reason) before any composer spawn.
    require_native_snapshot_runtime(business=business_policy is not None)
    effective_policy = effective_native_policy_v3(config, deadline_monotonic=deadline_monotonic)
    binding = capture_native_command_control_binding(command_extensions) if command_extensions is not None else None
    raw_mode = _config_value(config, "mode", "prompt")
    if not isinstance(raw_mode, str) or raw_mode not in _VALID_INPUT_MODES:
        raise NativePolicySnapshotError("native_policy_snapshot_mode_invalid")
    mode = "observe" if raw_mode == "observe" or effective_policy["protection_posture"] == "watch" else "enforce"
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
    from .native_policy_snapshot_business_bridge import build_native_business_snapshot, capture_business_binding

    request: dict[str, object] = {
        "generation": generation,
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
    }
    if binding is not None:
        request["command_extensions"] = binding
    if business_policy is not None:
        request["business_policy"] = capture_business_binding(business_policy)
    key = list(verifier_key)
    try:
        request.update(schema="guard-native-policy-build.v1", version=1, verifier_key=key)
        # The resident-built snapshot is the only authority. Python verifies the
        # returned binding and MAC but never recalculates digests or policy.
        built = build_native_business_snapshot(request, deadline_monotonic=deadline_monotonic)
        integrity = built.get("integrity")
        if (
            not isinstance(integrity, Mapping)
            or integrity.get("key_id") != native_policy_verifier_key_id(verifier_key)
            or not snapshot_mac_matches_v3(built, verifier_key)
        ):
            raise NativePolicySnapshotError("native_policy_snapshot_cache_integrity_invalid")
        return built
    finally:
        # Drop owned references only. CPython's shared integers, immutable
        # caller bytes and JSON/subprocess copies cannot be reliably wiped.
        # This transport does not establish secret custody or zeroization.
        key.clear()
        request.pop("verifier_key", None)


def snapshot_bytes_v3(snapshot: Mapping[str, object]) -> bytes:
    """Canonical bounded encoding; semantic validation is resident-owned."""

    _validate_json_limits_v3(snapshot)
    encoded = _canonical_json_bytes_v3(snapshot)
    if len(encoded) > POLICY_SNAPSHOT_MAX_BYTES:
        raise NativePolicySnapshotError("native_policy_snapshot_too_large")
    return encoded


def _policy_snapshot_push_bytes_v3(
    snapshot: Mapping[str, object],
    *,
    deadline_budget_ms: int | None = None,
    direct_lane: Mapping[str, object] | None = None,
) -> bytes:
    """Build the strict resident push envelope; the resident validates the snapshot."""

    _validate_json_limits_v3(snapshot)
    budget = int(_PUBLISH_TIMEOUT_SECONDS * 1_000) if deadline_budget_ms is None else deadline_budget_ms
    if type(budget) is not int or not 1 <= budget <= 9_000:
        raise NativePolicySnapshotError("native_policy_snapshot_push_invalid")
    request: dict[str, object] = {"schema": POLICY_SNAPSHOT_PUSH_SCHEMA, "snapshot": snapshot}
    if direct_lane is not None:
        request["direct_lane"] = direct_lane
    envelope = {"operation": "policy_snapshot_push", "deadline_budget_ms": budget, "request": request}
    encoded = _canonical_json_bytes_v3(envelope)
    if len(encoded) > POLICY_SNAPSHOT_MAX_BYTES:
        if direct_lane is not None:
            # The binding is optional; never let it cost the publication.
            return _policy_snapshot_push_bytes_v3(snapshot, deadline_budget_ms=budget)
        raise NativePolicySnapshotError("native_policy_snapshot_too_large")
    return encoded
