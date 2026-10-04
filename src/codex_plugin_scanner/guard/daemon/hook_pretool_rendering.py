"""Render native pre-tool decisions without changing their policy floor."""

from collections.abc import Mapping
from pathlib import Path

from .hook_worker_responses import (
    _GROK_DECISION_HARNESSES,
    _SILENT_WARNING_CODES,
    _attach_native_review_approval_aliases,
    _canonical_hook_harness,
    _native_review_permission_decision,
    _native_review_reason,
)


def harness_json_from_native_pre_tool(harness: str, response: Mapping[str, object]) -> dict[str, object]:
    action = response.get("minimum_action")
    reason = str(response.get("reason") or "HOL Guard requires native review before execution.")
    reason_code = str(response.get("reason_code") or "native_pre_tool_review")
    canonical = _canonical_hook_harness(harness)
    if (
        canonical in {"omp", "zcode"}
        and action == "sandbox-required"
        and response.get("policy_action") == "sandbox-required"
        and response.get("decision") == "deny"
        and response.get("authority") == "rust"
        and response.get("schema") == "guard-pre-tool-result.v1"
        and reason_code
        in {
            "native_pytest_readonly_containment_required",
            "native_node_test_readonly_containment_required",
            "native_vitest_readonly_containment_required",
            "native_package_test_readonly_containment_required",
            "native_python_eval_readonly_containment_required",
            "native_node_eval_readonly_containment_required",
            "native_git_readonly_containment_required",
            "native_node_tool_readonly_containment_required",
            "native_node_build_output_containment_required",
        }
    ):
        extensions = response.get("command_extensions")
        binding = extensions.get("binding") if isinstance(extensions, Mapping) else None
        observations = extensions.get("observations") if isinstance(extensions, Mapping) else None
        permission_observations = extensions.get("permission_observations") if isinstance(extensions, Mapping) else None
        if (
            isinstance(extensions, Mapping)
            and isinstance(binding, Mapping)
            and type(binding.get("uncertainty_count")) is int
            and binding["uncertainty_count"] == 0
            and extensions.get("evaluation_error") is None
            and (
                observations == []
                or (
                    reason_code == "native_git_readonly_containment_required"
                    and isinstance(observations, list)
                    and all(
                        isinstance(item, Mapping)
                        and item.get("rule_id") in {"command.git.diff", "command.git.log", "command.git.show"}
                        and item.get("uncertainty_reasons") == []
                        and item.get("effective_segment_indexes") == [0]
                        for item in observations
                    )
                )
            )
            and (
                permission_observations == []
                or (
                    reason_code
                    in {
                        "native_vitest_readonly_containment_required",
                        "native_package_test_readonly_containment_required",
                        "native_node_tool_readonly_containment_required",
                        "native_node_build_output_containment_required",
                    }
                    and isinstance(permission_observations, list)
                    and all(
                        isinstance(item, Mapping)
                        and item.get("extension_id") == "command.package.node"
                        and item.get("permission_id") == "command.package.node.permission.package-protection"
                        and item.get("uncertainty_reasons") == []
                        for item in permission_observations
                    )
                )
            )
        ):
            # This is not permission to execute the original input. New adapters
            # may route it to the protected sink; old adapters still see deny.
            receipt: dict[str, object] = {
                "decision": "deny",
                "policy_action": "sandbox-required",
                "reason_code": reason_code,
                "reason": reason,
                "required_execution_profile": {
                    "native_python_eval_readonly_containment_required": "python-eval-readonly-v1",
                    "native_node_eval_readonly_containment_required": "node-eval-readonly-v1",
                    "native_package_test_readonly_containment_required": "package-test-readonly-v1",
                    "native_node_build_output_containment_required": "node-build-output-v1",
                    "native_node_tool_readonly_containment_required": "node-tool-readonly-v1",
                    "native_git_readonly_containment_required": "git-readonly-v1",
                    "native_vitest_readonly_containment_required": "vitest-readonly-v1",
                    "native_node_test_readonly_containment_required": "node-test-readonly-v1",
                    "native_pytest_readonly_containment_required": "pytest-readonly-v2",
                }[reason_code],
            }
            if canonical == "zcode":
                receipt["hookSpecificOutput"] = {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "deny",
                    "permissionDecisionReason": reason,
                }
            return receipt
    if action in {"allow", "warn"} and response.get("decision") == "allow":
        if canonical in {"pi", "omp"}:
            output: dict[str, object] = {
                "decision": "allow",
                "policy_action": action,
                "reason_code": reason_code,
            }
            if action == "warn" and reason_code not in _SILENT_WARNING_CODES:
                output["reason"] = reason
                output["notice"] = "warning"
            return output
        hook_specific: dict[str, object] = {
            "hookEventName": "PreToolUse",
            "permissionDecision": "allow",
        }
        if action == "warn" and reason_code not in _SILENT_WARNING_CODES:
            hook_specific["permissionDecisionReason"] = reason
        if canonical in _GROK_DECISION_HARNESSES:
            grok_allow: dict[str, object] = {
                "decision": "allow",
                "policy_action": action,
                "reason_code": reason_code,
                "hookSpecificOutput": hook_specific,
            }
            if action == "warn" and reason_code not in _SILENT_WARNING_CODES:
                grok_allow["reason"] = reason
            return grok_allow
        return {
            "continue": True,
            "policy_action": action,
            "reason_code": reason_code,
            "hookSpecificOutput": hook_specific,
        }
    if canonical in {"pi", "omp"}:
        return {
            "decision": "deny",
            "reason": reason,
            "model_output_action": "block",
            "notice": "warning",
            "policy_action": "block",
            "reason_code": reason_code,
        }
    hook_specific_deny: dict[str, object] = {
        "hookEventName": "PreToolUse",
        "permissionDecision": "deny",
        "permissionDecisionReason": reason,
    }
    if canonical in _GROK_DECISION_HARNESSES:
        return {
            "decision": "deny",
            "reason": reason,
            "policy_action": "block",
            "reason_code": reason_code,
            "hookSpecificOutput": hook_specific_deny,
        }
    return {
        "policy_action": "block",
        "reason_code": reason_code,
        "hookSpecificOutput": hook_specific_deny,
    }


def harness_json_from_native_pre_tool_review(
    harness: str,
    response: Mapping[str, object],
    *,
    approval: Mapping[str, object] | None,
    guard_home: Path | None = None,
) -> dict[str, object]:
    """Pause a native review without treating it as a terminal block."""

    reason = str(response.get("reason") or "HOL Guard requires review before this action can execute.")
    reason_code = str(response.get("reason_code") or "native_pre_tool_review")
    canonical = _canonical_hook_harness(harness)
    approval_url = None
    approval_request_id = None
    if approval is not None:
        raw_url = approval.get("approval_url")
        raw_request_id = approval.get("request_id")
        if isinstance(raw_url, str) and raw_url.strip():
            approval_url = raw_url.strip()
            reason = _native_review_reason(
                canonical,
                reason,
                approval_url,
                guard_home=guard_home,
            )
        if isinstance(raw_request_id, str) and raw_request_id.strip():
            approval_request_id = raw_request_id.strip()
    permission_decision = _native_review_permission_decision(harness)
    if canonical in {"pi", "omp"}:
        output: dict[str, object] = {
            "decision": "deny",
            "reason": reason,
            "model_output_action": "block",
            "notice": "warning",
            "policy_action": "review",
            "reason_code": reason_code,
        }
        if approval_url is not None:
            output["approval_url"] = approval_url
        if approval_request_id is not None:
            output["approval_request_id"] = approval_request_id
        _attach_native_review_approval_aliases(output, approval_request_id, approval_url)
        return output
    hook_specific: dict[str, object] = {
        "hookEventName": "PreToolUse",
        "permissionDecision": permission_decision,
        "permissionDecisionReason": reason,
    }
    rendered: dict[str, object] = {
        "policy_action": "review",
        "reason_code": reason_code,
        "reason": reason,
        "hookSpecificOutput": hook_specific,
    }
    if canonical in _GROK_DECISION_HARNESSES:
        rendered["decision"] = "deny"
    if approval_url is not None:
        rendered["approval_url"] = approval_url
    if approval_request_id is not None:
        rendered["approval_request_id"] = approval_request_id
    _attach_native_review_approval_aliases(rendered, approval_request_id, approval_url)
    return rendered
