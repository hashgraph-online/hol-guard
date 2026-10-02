"""Canonical native-workspace fields used by local review claims."""

from __future__ import annotations

import json
from collections.abc import Mapping

from .stable_digest import sha256_content_digest
from .stable_json import stable_json_serialize

_NATIVE_ACTION_BINDING_DOMAIN = "guard-native-workspace-review-action-binding-v1\0"
_NATIVE_INTENT_BINDING_DOMAIN = "guard-native-workspace-review-intent-binding-v1\0"
_NATIVE_POLICY_BINDING_DOMAIN = "guard-native-workspace-review-policy-binding-v1\0"
NATIVE_BINDING_VERSION = "guard-native-workspace-review-bindings.v1"
_NATIVE_BINDING_DIGEST_DOMAIN = "guard-native-workspace-review-bindings.v1\0"
NATIVE_BINDING_FIELDS = ("nativeActionBinding", "nativeIntentBinding", "nativePolicyBinding")
_NATIVE_BINDING_COMPARISON_FIELDS = ("nativeBindingVersion", "nativeBindingDigest", *NATIVE_BINDING_FIELDS)


def _sha256_hex(value: str) -> str:
    return sha256_content_digest(value.encode("utf-8"))


def _native_json_value(request_row: dict[str, object], field: str) -> tuple[object, bool]:
    value = request_row.get(field)
    if not isinstance(value, str):
        return value, True
    try:
        return json.loads(value), True
    except (json.JSONDecodeError, TypeError, ValueError):
        return None, False


def _native_binding_digest(value: dict[str, object], domain: str) -> str:
    return _sha256_hex(domain + stable_json_serialize(value))


def _valid_binding(value: object) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(char in "0123456789abcdef" for char in value)


def native_binding_commitment(bindings: Mapping[str, object]) -> str:
    values = {field: bindings.get(field) for field in NATIVE_BINDING_FIELDS}
    return _sha256_hex(_NATIVE_BINDING_DIGEST_DOMAIN + stable_json_serialize(values))


def native_binding_commitment_matches(claim: Mapping[str, object]) -> bool:
    return (
        claim.get("nativeBindingVersion") == NATIVE_BINDING_VERSION
        and all(_valid_binding(claim.get(field)) for field in NATIVE_BINDING_FIELDS)
        and isinstance(claim.get("nativeBindingDigest"), str)
        and claim.get("nativeBindingDigest") == native_binding_commitment(claim)
    )


def native_binding_values_match(left: Mapping[str, object], right: Mapping[str, object]) -> bool:
    """Compare the complete versioned native commitment, including raw bindings."""

    return all(left.get(field) == right.get(field) for field in _NATIVE_BINDING_COMPARISON_FIELDS)


def canonical_native_launch_target(request_row: dict[str, object]) -> object:
    launch_target = request_row.get("launch_target")
    normalized_identity = request_row.get("normalized_identity_key")
    if not isinstance(launch_target, str) or not isinstance(normalized_identity, str):
        return launch_target
    identity_parts = normalized_identity.split()
    if (
        len(identity_parts) == 3
        and identity_parts[2] == "unknown"
        and launch_target.startswith(f"{identity_parts[0]} {identity_parts[1]} ")
    ):
        return normalized_identity
    return launch_target


def native_review_claim_bindings(request_row: dict[str, object]) -> dict[str, object | None]:
    action_envelope, action_valid = _native_json_value(request_row, "action_envelope_json")
    browser_intent, intent_valid = _native_json_value(request_row, "browser_intent_json")
    if browser_intent is None and "browser_intent" in request_row:
        browser_intent, intent_valid = _native_json_value(request_row, "browser_intent")
    decision_v2, policy_valid = _native_json_value(request_row, "decision_v2_json")
    action = {
        "action_identity": request_row.get("action_identity"),
        "action_envelope": action_envelope,
        "launch_target": canonical_native_launch_target(request_row),
        "raw_command_text": request_row.get("raw_command_text"),
    }
    intent = {
        "harness": request_row.get("harness"),
        "artifact_id": request_row.get("artifact_id"),
        "artifact_type": request_row.get("artifact_type"),
        "workspace": request_row.get("workspace"),
        "browser_intent": browser_intent,
    }
    policy = {
        "policy_action": request_row.get("policy_action"),
        "recommended_scope": request_row.get("recommended_scope"),
        "source_scope": request_row.get("source_scope"),
        "decision_v2": decision_v2,
    }
    bindings: dict[str, object | None] = {
        "nativeActionBinding": (
            _native_binding_digest(action, _NATIVE_ACTION_BINDING_DOMAIN) if action_valid else None
        ),
        "nativeIntentBinding": (
            _native_binding_digest(intent, _NATIVE_INTENT_BINDING_DOMAIN) if intent_valid else None
        ),
        "nativePolicyBinding": (
            _native_binding_digest(policy, _NATIVE_POLICY_BINDING_DOMAIN) if policy_valid else None
        ),
    }
    if all(_valid_binding(bindings.get(field)) for field in NATIVE_BINDING_FIELDS):
        bindings.update(
            {
                "nativeBindingVersion": NATIVE_BINDING_VERSION,
                "nativeBindingDigest": native_binding_commitment(bindings),
            }
        )
    return bindings
