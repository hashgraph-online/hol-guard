"""Policy snapshot v3 contract validation, signing, and encoding."""

from __future__ import annotations

import hashlib
import hmac
import time
from collections.abc import Mapping
from pathlib import Path
from typing import TYPE_CHECKING, cast

from .native_policy_snapshot_codec import (
    _canonical_json_bytes_v3,
    _digest_v3,
    _valid_bounded_string_v3,
    _validate_json_limits_v3,
    native_policy_verifier_key_id,
)
from .native_policy_snapshot_constants import (
    _EFFECTIVE_POLICY_FIELDS,
    _INTEGRITY_FIELDS,
    _MAX_U16,
    _MAX_U64,
    _PUBLISH_TIMEOUT_SECONDS,
    _PUSH_ENVELOPE_FIELDS,
    _PUSH_REQUEST_FIELDS,
    _SCOPE_FIELDS,
    _SNAPSHOT_FIELDS,
    _VALID_ACTIONS,
    _VALID_INPUT_MODES,
    _VALID_POSTURES,
    _VALID_REDACTION_LEVELS,
    _VALID_SANDBOX_ANALYSIS,
    _VALID_SECURITY_LEVELS,
    _VERIFIER_KEY_BYTES,
    POLICY_SNAPSHOT_INTEGRITY_ALGORITHM,
    POLICY_SNAPSHOT_INTEGRITY_DOMAIN,
    POLICY_SNAPSHOT_MAX_BYTES,
    POLICY_SNAPSHOT_MAX_EXPIRY_MS,
    POLICY_SNAPSHOT_PROTOCOL_VERSION,
    POLICY_SNAPSHOT_PUSH_SCHEMA,
    POLICY_SNAPSHOT_V3_SCHEMA,
    POLICY_SNAPSHOT_V3_VERSION,
    NativePolicySnapshotError,
)
from .native_policy_snapshot_policy import (
    _config_value,
    _harness_action_map,
    _harness_risk_map,
    _scope_digest_v3,
    _string_map,
    effective_native_policy_v3,
)

if TYPE_CHECKING:
    from .config import GuardConfig


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


def _validate_snapshot_metadata_v3(root: Mapping[str, object]) -> str:
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
    return cast(str, mode)


def _validate_snapshot_scope_v3(root: Mapping[str, object]) -> Mapping[str, object]:
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
    return scope


def _validate_snapshot_policy_v3(root: Mapping[str, object]) -> Mapping[str, object]:
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
    return effective


def _validate_snapshot_integrity_v3(root: Mapping[str, object], *, allow_empty_mac: bool) -> None:
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


def _verify_snapshot_digests_v3(
    root: Mapping[str, object],
    effective: Mapping[str, object],
    mode: str,
    scope: Mapping[str, object],
) -> None:
    effective_digest = _digest_v3(effective)
    if root.get("config_digest") != effective_digest:
        raise NativePolicySnapshotError("native_policy_snapshot_digest_mismatch")
    expected_policy_digest = _snapshot_policy_digest_v3(
        config_digest=cast(str, root["config_digest"]),
        effective_policy=effective,
        mode=mode,
        rule_digest=cast(str, root["rule_digest"]),
        runtime_identity=cast(str, root["runtime_identity"]),
        scope_digest=cast(str, scope["scope_digest"]),
    )
    if root.get("policy_digest") != expected_policy_digest:
        raise NativePolicySnapshotError("native_policy_snapshot_digest_mismatch")


def _validate_snapshot_v3(
    snapshot: Mapping[str, object],
    *,
    allow_empty_mac: bool = False,
    verify_digests: bool = True,
) -> None:
    """Apply the resident's typed v3 validation before signing or transport."""

    _validate_json_limits_v3(snapshot)
    root = _require_snapshot_mapping_fields_v3(snapshot, _SNAPSHOT_FIELDS)
    mode = _validate_snapshot_metadata_v3(root)
    scope = _validate_snapshot_scope_v3(root)
    effective = _validate_snapshot_policy_v3(root)
    _validate_snapshot_integrity_v3(root, allow_empty_mac=allow_empty_mac)
    if verify_digests:
        _verify_snapshot_digests_v3(root, effective, mode, scope)


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
