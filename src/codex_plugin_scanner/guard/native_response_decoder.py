"""Bounded decoding for responses returned by the native hook runtime."""

from __future__ import annotations

from codex_plugin_scanner.guard.runtime.hook_review_types import HookReviewResponse

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


def response_from_payload(payload: object) -> HookReviewResponse | None:
    """Decode one strict native response without assigning new semantics."""

    if not isinstance(payload, dict):
        return None
    if payload.get("schema") == "guard-hook-edge-result.v2":
        if set(payload) - {
            "schema",
            "authority",
            "request_id",
            "harness",
            "event_name",
            "payload_kind",
            "result",
        }:
            return None
        if (
            payload.get("authority") != "rust"
            or payload.get("event_name") != "PostToolUse"
            or payload.get("payload_kind") not in {"inline", "source_file_ref", "encrypted_payload_ref"}
            or not isinstance(payload.get("harness"), str)
            or not payload["harness"]
            or len(payload["harness"]) > 64
            or not isinstance(payload.get("result"), dict)
        ):
            return None
        request_id = payload.get("request_id")
        if request_id is not None and (not isinstance(request_id, str) or len(request_id) > 256):
            return None
        payload = payload["result"]
    decision = payload.get("decision")
    model_output_action = payload.get("model_output_action")
    notice = payload.get("notice")
    reason_code = payload.get("reason_code")
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
    reason = payload.get("reason")
    reviewed_output_sha256 = payload.get("reviewed_output_sha256")
    reviewed_excerpt = payload.get("reviewed_excerpt")
    policy_action = payload.get("policy_action")
    observed_policy_action = payload.get("observed_policy_action")
    return HookReviewResponse(
        decision=decision,
        reason=reason if isinstance(reason, str) else None,
        model_output_action=model_output_action,
        reviewed_output_sha256=reviewed_output_sha256 if isinstance(reviewed_output_sha256, str) else None,
        reviewed_excerpt=reviewed_excerpt if isinstance(reviewed_excerpt, str) else None,
        notice=notice,
        reason_code=reason_code,
        policy_action=policy_action if isinstance(policy_action, str) else None,
        observed_policy_action=observed_policy_action if isinstance(observed_policy_action, str) else None,
        observe_mode=payload.get("observe_mode") is True,
    )


def native_error(payload: object) -> str | None:
    """Return a known native transport error from a strict error envelope."""

    if not isinstance(payload, dict) or set(payload) - {"error", "retryable"}:
        return None
    error = payload.get("error")
    if not isinstance(error, str) or error not in _NATIVE_ERROR_CODES:
        return None
    retryable = payload.get("retryable")
    if retryable is not None and not isinstance(retryable, bool):
        return None
    return error


__all__ = ["native_error", "response_from_payload"]
