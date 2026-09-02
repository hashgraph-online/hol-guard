"""Mechanical harness response rendering for the daemon hook worker."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .hook_availability_policy import hook_action_is_emergency_safe


def prepare_native_hook_policy(
    handler: Any,
    daemon_server: Any,
    payload: dict[str, object],
    params: Mapping[str, list[str]],
    default_harness: str,
    workspace: str | None,
    deadline: float,
) -> bool:
    """Apply the production native-policy barrier before hook admission."""

    workspace_path = Path(workspace) if workspace is not None else None
    prepared_policy = daemon_server.hook_worker.prepare_workspace_policy(
        workspace_path,
        deadline=deadline,
    )
    if prepared_policy is not None:
        return True
    if hook_action_is_emergency_safe(payload, workspace=workspace_path):
        return True
    daemon_server.hook_worker.metrics.record_route("native_fail_safe")
    handler._write_json(
        handler._runtime_hook_fail_safe_response(
            payload,
            params,
            default_harness=default_harness,
            reason="HOL Guard could not prepare the native policy safely.",
            reason_code="native_policy_not_ready",
            native_authoritative=True,
        )
    )
    return False


def _canonical_hook_harness(harness: str) -> str:
    return harness.strip().lower().replace("_", "-")


def harness_json_from_native_pre_tool(harness: str, response: Mapping[str, object]) -> dict[str, object]:
    action = response.get("minimum_action")
    reason = str(response.get("reason") or "HOL Guard requires native review before execution.")
    reason_code = str(response.get("reason_code") or "native_pre_tool_review")
    if action in {"allow", "warn"} and response.get("decision") == "allow":
        if _canonical_hook_harness(harness) in {"pi", "omp"}:
            output: dict[str, object] = {
                "decision": "allow",
                "policy_action": action,
                "reason_code": reason_code,
            }
            if action == "warn":
                output["reason"] = reason
                output["notice"] = "warning"
            return output
        hook_specific: dict[str, object] = {
            "hookEventName": "PreToolUse",
            "permissionDecision": "allow",
        }
        if action == "warn":
            hook_specific["permissionDecisionReason"] = reason
        return {
            "continue": True,
            "policy_action": action,
            "reason_code": reason_code,
            "hookSpecificOutput": hook_specific,
        }
    if _canonical_hook_harness(harness) in {"pi", "omp"}:
        return {
            "decision": "deny",
            "reason": reason,
            "model_output_action": "block",
            "notice": "warning",
            "policy_action": "block",
            "reason_code": reason_code,
        }
    return {
        "policy_action": "block",
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
        action = response.get("policy_action")
        if action not in {"allow", "warn"}:
            action = "allow"
        output: dict[str, object] = {
            "policy_action": action,
            "hookSpecificOutput": {"hookEventName": "PostToolUse"},
        }
        if action == "warn":
            output["hookSpecificOutput"] = {
                "hookEventName": "PostToolUse",
                "permissionDecisionReason": str(
                    response.get("reason")
                    or "HOL Guard raised a non-blocking warning under the installed native policy."
                ),
            }
        return output
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


def observe_lifecycle_fail_safe_response(
    harness: str,
    *,
    event_name: str,
    reason_code: str,
) -> dict[str, object]:
    """Continue prompt/session inventory hooks when native review cannot run."""

    canonical = _canonical_hook_harness(harness)
    if canonical in {"grok", "hermes", "openclaw", "pi", "omp"}:
        return {
            "decision": "allow",
            "policy_action": "allow",
            "reason_code": reason_code,
        }
    return {
        "continue": True,
        "policy_action": "allow",
        "reason_code": reason_code,
        "hookSpecificOutput": {"hookEventName": event_name},
    }


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
    "observe_lifecycle_fail_safe_response",
    "post_tool_fail_safe_response",
    "post_tool_native_block_response",
]
