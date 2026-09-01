"""Bounded decoding for responses returned by the native hook runtime."""

from __future__ import annotations

from typing import Literal, cast

from codex_plugin_scanner.guard.runtime.hook_review_types import HookDecision, HookReviewResponse, ModelOutputAction

from .native_approval_errors import NATIVE_APPROVAL_ERROR_CODES
from .native_approval_protocol import decode_native_approval_challenge, decode_native_approval_result

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
_NATIVE_APPROVAL_ERROR_CODES = NATIVE_APPROVAL_ERROR_CODES


def _string_dict(value: object) -> dict[str, object] | None:
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        return None
    return cast(dict[str, object], value)


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
