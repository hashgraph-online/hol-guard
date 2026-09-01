"""Bounded decoding for responses returned by the native hook runtime."""

from __future__ import annotations

import re
from typing import Literal, cast

from codex_plugin_scanner.guard.runtime.hook_review_types import HookDecision, HookReviewResponse, ModelOutputAction

_NATIVE_ERROR_CODES = frozenset(
    {
        "native_overloaded",
        "native_frame_read_failed",
        "native_request_digest_mismatch",
        "native_request_invalid_json",
        "native_request_too_large",
        "native_response_encode_failed",
        "native_runtime_panicked",
    }
)
_NATIVE_APPROVAL_ERROR_CODES = frozenset(
    {
        "native_approval_action_digest_failed",
        "native_approval_action_identity_invalid",
        "native_approval_action_not_approvable",
        "native_approval_action_reconstruction_failed",
        "native_approval_artifact_invalid",
        "native_approval_artifact_schema_mismatch",
        "native_approval_artifact_serialization_failed",
        "native_approval_artifact_too_large",
        "native_approval_authority_already_enrolled",
        "native_approval_authority_busy",
        "native_approval_authority_enrollment_invalid",
        "native_approval_authority_generation_invalid",
        "native_approval_authority_generation_rollback",
        "native_approval_authority_invalid",
        "native_approval_authority_key_id_mismatch",
        "native_approval_authority_lock_failed",
        "native_approval_authority_lock_invalid",
        "native_approval_authority_lock_not_private",
        "native_approval_authority_missing",
        "native_approval_authority_noncanonical",
        "native_approval_authority_provenance_mismatch",
        "native_approval_authority_recovery_pending",
        "native_approval_authority_revoked",
        "native_approval_authority_root_invalid",
        "native_approval_authority_root_provenance_invalid",
        "native_approval_authority_root_provenance_unconfigured",
        "native_approval_authority_root_unconfigured",
        "native_approval_binding_ambiguous",
        "native_approval_binding_invalid",
        "native_approval_binding_mismatch",
        "native_approval_challenge_request_invalid",
        "native_approval_clock_invalid",
        "native_approval_consume_request_invalid",
        "native_approval_consumed",
        "native_approval_device_identity_invalid",
        "native_approval_digest_invalid",
        "native_approval_edge_result_invalid",
        "native_approval_edge_result_too_large",
        "native_approval_enrollment_request_invalid",
        "native_approval_enrollment_required",
        "native_approval_failed",
        "native_approval_floor_mismatch",
        "native_approval_floor_not_approvable",
        "native_approval_floor_not_overridable",
        "native_approval_integrity_invalid",
        "native_approval_integrity_mismatch",
        "native_approval_intrinsic_action_invalid",
        "native_approval_minimum_action_invalid",
        "native_approval_nonce_invalid",
        "native_approval_policy_context_mismatch",
        "native_approval_random_failed",
        "native_approval_receipt_consumed",
        "native_approval_receipt_expired",
        "native_approval_receipt_invalid",
        "native_approval_receipt_not_claimed",
        "native_approval_replay",
        "native_approval_replay_full",
        "native_approval_replay_unavailable",
        "native_approval_request_bounds_exceeded",
        "native_approval_request_id_mismatch",
        "native_approval_request_id_missing",
        "native_approval_response_too_large",
        "native_approval_result_invalid",
        "native_approval_runtime_mismatch",
        "native_approval_secure_state_invalid",
        "native_approval_secure_state_unavailable",
        "native_approval_signing_authority_replaced",
        "native_approval_signing_authority_unavailable",
        "native_approval_time_invalid",
        "native_approval_validate_request_invalid",
        "native_approval_validated",
    }
)
_APPROVAL_HEX64 = re.compile(r"[0-9a-f]{64}")
_APPROVAL_NONCE_HEX = re.compile(r"[0-9a-f]{64}")
_APPROVAL_ACTION_TYPES = frozenset(
    {
        "command",
        "file_read",
        "file_write",
        "package",
        "mcp_tool",
        "network",
        "process_service",
        "browser",
        "config",
        "prompt",
        "harness",
        "unknown",
    }
)
_APPROVAL_OPERATIONS = frozenset(
    {"execute", "read", "write", "install", "call", "request", "start", "stop", "navigate", "set", "submit", "unknown"}
)
_APPROVAL_FLOORS = frozenset({"review", "require-reapproval", "sandbox-required", "block"})
_APPROVAL_CHALLENGE_KEYS = frozenset(
    {
        "schema",
        "version",
        "request_id",
        "request_digest",
        "action_digest",
        "action_type",
        "operation",
        "intrinsic_action",
        "minimum_action",
        "floor_class",
        "approval_eligible",
        "policy_generation",
        "policy_digest",
        "rule_digest",
        "runtime_identity",
        "runtime_protocol_version",
        "runtime_package",
        "runtime_version",
        "runtime_binary_identity",
        "harness",
        "workspace_binding",
        "device_binding",
        "installation_binding",
        "publisher_binding",
        "artifact_binding",
        "scope_contract_version",
        "scope_contract_digest",
        "scope_binding",
        "resident_epoch",
        "nonce",
        "issued_at_ms",
        "expires_at_ms",
        "requested_action",
        "signing_key_id",
    }
)
_APPROVAL_RESULT_KEYS = frozenset({"schema", "version", "authority", "receipt"})
_APPROVAL_RECEIPT_KEYS = frozenset(
    {
        "schema",
        "version",
        "phase",
        "request_id",
        "request_digest",
        "action_digest",
        "policy_generation",
        "policy_digest",
        "rule_digest",
        "runtime_identity",
        "runtime_protocol_version",
        "runtime_package",
        "runtime_version",
        "runtime_binary_identity",
        "harness",
        "workspace_binding",
        "device_binding",
        "installation_binding",
        "publisher_binding",
        "artifact_binding",
        "scope_contract_version",
        "scope_contract_digest",
        "scope_binding",
        "resident_epoch",
        "nonce",
        "issued_at_ms",
        "expires_at_ms",
        "decision",
        "requested_action",
        "approved_action",
        "reason_code",
        "nonce_digest",
        "replay_claimed",
    }
)
_APPROVAL_REASON_CODES = frozenset({"native_approval_validated", "native_approval_consumed"})
_APPROVAL_MAX_TTL_MS = 15 * 60 * 1000


def _bounded_approval_text(value: object, *, maximum: int, nonempty: bool = True) -> bool:
    return (
        isinstance(value, str)
        and (not nonempty or bool(value))
        and len(value) <= maximum
        and len(value.encode("utf-8")) <= maximum
    )


def _approval_digest(value: object) -> bool:
    return isinstance(value, str) and _APPROVAL_HEX64.fullmatch(value) is not None


def _approval_optional_digest(value: object) -> bool:
    return value is None or _approval_digest(value)


def _approval_positive_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def _approval_bounded_text(value: object, *, maximum: int = 256) -> bool:
    return _bounded_approval_text(value, maximum=maximum)


def _string_dict(value: object) -> dict[str, object] | None:
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        return None
    return cast(dict[str, object], value)


def _approval_request_id(value: object) -> bool:
    if not _bounded_approval_text(value, maximum=256):
        return False
    assert isinstance(value, str)
    return all(character.islower() or character.isdigit() or character in "-_.:" for character in value)


def _approval_challenge_is_safe(payload: dict[str, object]) -> bool:
    if set(payload) != _APPROVAL_CHALLENGE_KEYS:
        return False
    if (
        payload.get("schema") != "guard-native-approval-challenge.v3"
        or payload.get("version") != 3
        or payload.get("floor_class") != "approvable"
        or payload.get("approval_eligible") is not True
        or payload.get("runtime_protocol_version") != 1
        or payload.get("requested_action") not in {"review", "require-reapproval"}
        or payload.get("action_type") not in _APPROVAL_ACTION_TYPES
        or payload.get("operation") not in _APPROVAL_OPERATIONS
        or not _approval_request_id(payload.get("request_id"))
        or not _approval_digest(payload.get("request_digest"))
        or not _approval_digest(payload.get("action_digest"))
        or not _approval_digest(payload.get("policy_digest"))
        or not _approval_digest(payload.get("rule_digest"))
        or not _approval_digest(payload.get("runtime_identity"))
        or not _approval_digest(payload.get("runtime_binary_identity"))
        or not _approval_digest(payload.get("scope_contract_digest"))
        or not _approval_digest(payload.get("resident_epoch"))
        or not _approval_digest(payload.get("signing_key_id"))
        or not _approval_nonce(payload.get("nonce"))
        or not _approval_positive_int(payload.get("policy_generation"))
        or not _approval_positive_int(payload.get("issued_at_ms"))
        or not _approval_positive_int(payload.get("expires_at_ms"))
        or payload["expires_at_ms"] <= payload["issued_at_ms"]
        or payload["expires_at_ms"] - payload["issued_at_ms"] > _APPROVAL_MAX_TTL_MS
    ):
        return False
    for key in ("intrinsic_action", "minimum_action"):
        if payload.get(key) not in _APPROVAL_FLOORS:
            return False
    for key in ("runtime_package", "runtime_version", "harness", "scope_contract_version"):
        if not _approval_bounded_text(payload.get(key)):
            return False
    for key in (
        "workspace_binding",
        "device_binding",
        "installation_binding",
        "publisher_binding",
        "artifact_binding",
        "scope_binding",
    ):
        if not _approval_optional_digest(payload.get(key)):
            return False
    return True


def _approval_nonce(value: object) -> bool:
    return isinstance(value, str) and _APPROVAL_NONCE_HEX.fullmatch(value) is not None


def decode_native_approval_challenge(payload: object) -> dict[str, object] | None:
    """Decode only a privacy-safe Rust challenge; never infer action semantics."""

    decoded = _string_dict(payload)
    if decoded is None:
        return None
    return decoded if _approval_challenge_is_safe(decoded) else None


def decode_native_approval_result(
    payload: object,
    *,
    phase: Literal["validated", "consumed"],
) -> dict[str, object] | None:
    """Accept only an authenticated Rust receipt for the requested phase."""

    decoded = _string_dict(payload)
    if decoded is None or set(decoded) != _APPROVAL_RESULT_KEYS:
        return None
    if decoded.get("schema") != "guard-native-approval-result.v3" or decoded.get("version") != 3:
        return None
    if decoded.get("authority") != "rust":
        return None
    receipt = _string_dict(decoded.get("receipt"))
    if receipt is None or set(receipt) != _APPROVAL_RECEIPT_KEYS:
        return None
    if (
        receipt.get("schema") != "guard-native-approval-receipt.v3"
        or receipt.get("version") != 3
        or receipt.get("phase") != phase
        or not _approval_request_id(receipt.get("request_id"))
        or not _approval_digest(receipt.get("request_digest"))
        or not _approval_digest(receipt.get("action_digest"))
        or not _approval_positive_int(receipt.get("policy_generation"))
        or receipt.get("runtime_protocol_version") != 1
        or not _approval_digest(receipt.get("policy_digest"))
        or not _approval_digest(receipt.get("rule_digest"))
        or not _approval_digest(receipt.get("runtime_identity"))
        or not _approval_digest(receipt.get("runtime_binary_identity"))
        or not _approval_digest(receipt.get("scope_contract_digest"))
        or not _approval_digest(receipt.get("resident_epoch"))
        or not _approval_nonce(receipt.get("nonce"))
        or not _approval_positive_int(receipt.get("issued_at_ms"))
        or not _approval_positive_int(receipt.get("expires_at_ms"))
        or receipt["expires_at_ms"] <= receipt["issued_at_ms"]
        or receipt["expires_at_ms"] - receipt["issued_at_ms"] > _APPROVAL_MAX_TTL_MS
        or receipt.get("decision") != "allow"
        or receipt.get("requested_action") not in {"review", "require-reapproval"}
        or receipt.get("approved_action") != "allow"
        or receipt.get("reason_code") != f"native_approval_{phase}"
        or receipt.get("reason_code") not in _APPROVAL_REASON_CODES
        or not _approval_digest(receipt.get("nonce_digest"))
        or receipt.get("replay_claimed") is not True
    ):
        return None
    for key in ("runtime_package", "runtime_version", "harness", "scope_contract_version"):
        if not _approval_bounded_text(receipt.get(key)):
            return None
    for key in (
        "workspace_binding",
        "device_binding",
        "installation_binding",
        "publisher_binding",
        "artifact_binding",
        "scope_binding",
    ):
        if not _approval_optional_digest(receipt.get(key)):
            return None
    return decoded


def response_from_payload(payload: object) -> HookReviewResponse | None:
    """Decode one strict native response without assigning new semantics."""

    if not isinstance(payload, dict):
        return None
    decoded = cast(dict[str, object], payload)
    if decoded.get("schema") == "guard-hook-edge-result.v2":
        if set(decoded) - {
            "schema",
            "authority",
            "request_id",
            "harness",
            "event_name",
            "payload_kind",
            "result",
        }:
            return None
        harness = decoded.get("harness")
        if (
            decoded.get("authority") != "rust"
            or decoded.get("event_name") != "PostToolUse"
            or decoded.get("payload_kind") not in {"inline", "source_file_ref", "encrypted_payload_ref"}
            or not isinstance(harness, str)
            or not harness
            or len(harness) > 64
            or not isinstance(decoded.get("result"), dict)
        ):
            return None
        request_id = decoded.get("request_id")
        if request_id is not None and (not isinstance(request_id, str) or len(request_id) > 256):
            return None
        result = decoded.get("result")
        if not isinstance(result, dict):
            return None
        decoded = cast(dict[str, object], result)
    decision = decoded.get("decision")
    model_output_action = decoded.get("model_output_action")
    notice = decoded.get("notice")
    reason_code = decoded.get("reason_code")
    if decision not in {"allow", "deny"}:
        return None
    if model_output_action not in {
        "allow_original",
        "replace_with_reviewed_excerpt",
        "block",
        "not_applicable",
    }:
        return None
    if notice not in {"none", "excerpt", "warning"} or not isinstance(reason_code, str):
        return None
    decision_value = cast(HookDecision, decision)
    model_output_action_value = cast(ModelOutputAction, model_output_action)
    notice_value = cast(Literal["none", "excerpt", "warning"], notice)
    reason = decoded.get("reason")
    reviewed_output_sha256 = decoded.get("reviewed_output_sha256")
    reviewed_excerpt = decoded.get("reviewed_excerpt")
    policy_action = decoded.get("policy_action")
    observed_policy_action = decoded.get("observed_policy_action")
    return HookReviewResponse(
        decision=decision_value,
        reason=reason if isinstance(reason, str) else None,
        model_output_action=model_output_action_value,
        reviewed_output_sha256=reviewed_output_sha256 if isinstance(reviewed_output_sha256, str) else None,
        reviewed_excerpt=reviewed_excerpt if isinstance(reviewed_excerpt, str) else None,
        notice=notice_value,
        reason_code=reason_code,
        policy_action=policy_action if isinstance(policy_action, str) else None,
        observed_policy_action=observed_policy_action if isinstance(observed_policy_action, str) else None,
        observe_mode=decoded.get("observe_mode") is True,
    )


def native_error(payload: object) -> str | None:
    """Return a known native transport error from a strict error envelope."""

    decoded = _string_dict(payload)
    if decoded is None or set(decoded) - {"error", "retryable"}:
        return None
    error = decoded.get("error")
    if not isinstance(error, str) or error not in (_NATIVE_ERROR_CODES | _NATIVE_APPROVAL_ERROR_CODES):
        return None
    retryable = decoded.get("retryable")
    if retryable is not None and not isinstance(retryable, bool):
        return None
    return error


__all__ = [
    "decode_native_approval_challenge",
    "decode_native_approval_result",
    "native_error",
    "response_from_payload",
]
