"""Bounded JSON, digest, and key primitives for native policy snapshots."""

from __future__ import annotations

import hashlib
import hmac
import json
import math
from collections.abc import Mapping

from .native_policy_snapshot_constants import (
    _VERIFIER_KEY_BYTES,
    POLICY_SNAPSHOT_MAX_JSON_COLLECTION_ITEMS,
    POLICY_SNAPSHOT_MAX_JSON_DEPTH,
    POLICY_SNAPSHOT_MAX_JSON_STRING_BYTES,
    POLICY_SNAPSHOT_MAX_STRING_BYTES,
    POLICY_SNAPSHOT_VERIFIER_DERIVATION_DOMAIN,
    NativePolicySnapshotError,
)


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


def _valid_digest_v3(value: object) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(character in "0123456789abcdef" for character in value)


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
