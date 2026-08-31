"""Mechanical harness response rendering for the daemon hook worker."""

from __future__ import annotations

from collections.abc import Mapping


def _canonical_hook_harness(harness: str) -> str:
    return harness.strip().lower().replace("_", "-")


def harness_json_from_native_pre_tool(harness: str, response: Mapping[str, object]) -> dict[str, object]:
    action = response.get("minimum_action")
    reason = str(response.get("reason") or "HOL Guard requires native review before execution.")
    reason_code = str(response.get("reason_code") or "native_pre_tool_review")
    if action == "allow" and response.get("decision") == "allow":
        if _canonical_hook_harness(harness) in {"pi", "omp"}:
            return {
                "decision": "allow",
                "policy_action": "allow",
                "reason_code": reason_code,
            }
        return {
            "continue": True,
            "policy_action": "allow",
            "reason_code": reason_code,
            "hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "allow"},
        }
    if _canonical_hook_harness(harness) in {"pi", "omp"}:
        return {
            "decision": "deny",
            "reason": reason,
            "model_output_action": "block",
            "notice": "warning",
            "reason_code": reason_code,
        }
    return {
        "reason_code": reason_code,
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        },
    }


def harness_json_from_native_post_tool(
    harness: str,
    response: Mapping[str, object],
) -> dict[str, object]:
    if _canonical_hook_harness(harness) in {"pi", "omp"}:
        return dict(response)
    if response.get("decision") == "allow" and response.get("model_output_action") == "allow_original":
        return {
            "policy_action": "allow",
            "hookSpecificOutput": {"hookEventName": "PostToolUse"},
        }
    reason = str(response.get("reason") or "HOL Guard blocked this tool output because it could not be proven safe.")
    reason_code = str(response.get("reason_code") or "native_hook_edge_block")
    return post_tool_native_block_response(reason=reason, reason_code=reason_code)


def post_tool_native_block_response(
    *,
    reason: str = "HOL Guard blocked this tool output because it could not be proven safe.",
    reason_code: str = "fast_path_block",
) -> dict[str, object]:
    return {
        "decision": "block",
        "reason": reason,
        "continue": False,
        "stopReason": reason,
        "policy_action": "block",
        "risk_summary": reason,
        "model_output_action": "block",
        "notice": "warning",
        "reason_code": reason_code,
    }


def post_tool_fail_safe_response(
    harness: str,
    *,
    reason: str = "HOL Guard could not complete local hook review safely.",
    reason_code: str = "daemon_worker_exception",
) -> dict[str, object]:
    if _canonical_hook_harness(harness) in {"pi", "omp"}:
        return {
            "decision": "deny",
            "reason": reason,
            "model_output_action": "block",
            "notice": "warning",
            "reason_code": reason_code,
        }
    return post_tool_native_block_response(reason=reason, reason_code=reason_code)


def harness_json_from_review_response(
    harness: str,
    event_name: str,
    response: object,
) -> dict[str, object]:
    to_harness_json = getattr(response, "to_harness_json", None)
    payload = to_harness_json() if callable(to_harness_json) else {}
    if not isinstance(payload, dict):
        payload = {}
    if event_name != "PostToolUse":
        return payload
    if _canonical_hook_harness(harness) in {"pi", "omp"}:
        return payload
    decision = str(payload.get("decision") or "")
    model_output_action = str(payload.get("model_output_action") or "")
    if decision == "allow" and model_output_action == "allow_original":
        return {
            "policy_action": "allow",
            "hookSpecificOutput": {"hookEventName": event_name},
        }
    reason = str(payload.get("reason") or "HOL Guard blocked this tool output because it could not be proven safe.")
    reason_code = str(payload.get("reason_code") or "fast_path_block")
    return post_tool_native_block_response(reason=reason, reason_code=reason_code)


__all__ = [
    "harness_json_from_native_post_tool",
    "harness_json_from_native_pre_tool",
    "harness_json_from_review_response",
    "post_tool_fail_safe_response",
    "post_tool_native_block_response",
]
