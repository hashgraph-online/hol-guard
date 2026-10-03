#[path = "generic_extract.rs"]
mod extract;
#[path = "generic_result.rs"]
mod result;

use crate::native_command_controls::CompiledNativeCommandControls;
use crate::CommandModelRequestV1;
use guard_contracts::{
    NativePromptRiskClassV1, PreToolActionTypeV1, PreToolOperationV1, PreToolResultV1,
};
use serde_json::Value;

use super::{evaluate_pre_tool_with_context, PreToolDecisionV1};
use extract::{extract_generic_signals, GenericSignals};
use result::{generic_action, generic_error_result, generic_result, review_reason};
use std::time::Instant;

#[path = "generic_tools.rs"]
mod tools;
use tools::{infer_action_type, package_command, tool_matches};

/// Evaluate the complete raw PreToolUse payload in native code. This stays
/// separate from `evaluate_pre_tool`, the compatibility command-model
/// operation used by older clients.
pub fn evaluate_pre_tool_envelope(harness: &str, event: &str, payload: &Value) -> PreToolResultV1 {
    evaluate_pre_tool_envelope_with_extensions(harness, event, payload, None, None)
}

pub fn evaluate_pre_tool_envelope_with_extensions(
    harness: &str,
    event: &str,
    payload: &Value,
    controls: Option<&CompiledNativeCommandControls>,
    deadline: Option<Instant>,
) -> PreToolResultV1 {
    evaluate_pre_tool_envelope_with_context(harness, event, payload, controls, deadline, None, None)
}

/// Like [`evaluate_pre_tool_envelope_with_extensions`] but also carries the
/// envelope's verified `home_dir`/`cwd` so `~/`-relative and absolute harness
/// paths (Devin sends `~/...` verbatim) share the non-sensitive read floor.
pub fn evaluate_pre_tool_envelope_with_context(
    harness: &str,
    event: &str,
    payload: &Value,
    controls: Option<&CompiledNativeCommandControls>,
    deadline: Option<Instant>,
    home_dir: Option<&str>,
    cwd: Option<&str>,
) -> PreToolResultV1 {
    let mut signals = match extract_generic_signals(payload) {
        Ok(value) => value,
        Err(error) => return generic_error_result(harness, event, error),
    };
    let command_decision = signals.command.as_deref().map(|command| {
        evaluate_pre_tool_with_context(
            &CommandModelRequestV1 {
                command: command.to_owned(),
                dialect: "posix".to_owned(),
                transport: "shell_string".to_owned(),
                extraction_provenance: "pre-tool-generic".to_owned(),
            },
            home_dir,
            cwd,
        )
    });
    // Parsed benign commands may contain credential words as search patterns.
    // Preserve independent structured-path/content risk, not the raw-text hint.
    if command_decision.as_ref().is_some_and(|decision| {
        decision
            .as_ref()
            .is_ok_and(|decision| decision.explicitly_benign)
    }) {
        signals.sensitive_target = signals.independent_sensitive_target;
    }
    let mut result = evaluate_signals(
        harness,
        event,
        &signals,
        command_decision.as_ref(),
        home_dir,
        cwd,
    );
    if event == "UserPromptSubmit" {
        let mut classes = Vec::new();
        if result.action.sensitive_target && signals.content_sensitive {
            classes.push(if signals.env_reference {
                NativePromptRiskClassV1::LocalEnvRead
            } else {
                NativePromptRiskClassV1::SensitiveMaterial
            });
        }
        if signals.exfil_intent {
            classes.push(NativePromptRiskClassV1::ExfilIntent);
        }
        if signals.destructive_intent {
            classes.push(NativePromptRiskClassV1::DestructiveIntent);
        }
        if signals.subprocess_intent {
            classes.push(NativePromptRiskClassV1::SubprocessIntent);
        }
        if signals.guard_bypass_intent {
            classes.push(NativePromptRiskClassV1::GuardBypassIntent);
        }
        if signals.prompt_injection_intent {
            classes.push(NativePromptRiskClassV1::PromptInjectionIntent);
        }
        result.prompt_risk_classes = classes;
    }
    let command_model = command_decision
        .as_ref()
        .and_then(|decision| decision.as_ref().ok())
        .map(|decision| &decision.command_model);
    let mut result = match (controls, command_model) {
        (Some(controls), Some(model)) => controls.apply_with_tool_and_context(
            Some(model),
            result,
            signals.tool_name.as_deref(),
            &signals.package_values,
            deadline,
            (home_dir, cwd),
        ),
        (Some(controls), _) => controls.apply_with_tool(
            None,
            result,
            signals.tool_name.as_deref(),
            &signals.package_values,
            deadline,
        ),
        _ => result,
    };
    let contained_test_reason =
        command_model.and_then(super::restricted_tests::readonly_test_reason);
    // The read-only credential-filtering backend currently exists on macOS.
    // Other platforms retain review until they can enforce the same profile.
    if cfg!(target_os = "macos")
        && event == "PreToolUse"
        && matches!(harness, "omp" | "oh-my-pi" | "zcode")
        && cwd.is_some()
        && (result.action.action_type == PreToolActionTypeV1::Command
            || (matches!(
                contained_test_reason,
                Some(
                    "native_vitest_readonly_containment_required"
                        | "native_package_test_readonly_containment_required"
                        | "native_node_tool_readonly_containment_required"
                        | "native_node_build_output_containment_required"
                )
            ) && result.action.action_type == PreToolActionTypeV1::Package))
        && !result.action.sensitive_target
        && (result.reason_code == "native_command_review_required"
            || (contained_test_reason == Some("native_git_readonly_containment_required")
                && result.reason_code == "native_git_helper_context_review")
            || (matches!(
                contained_test_reason,
                Some(
                    "native_node_tool_readonly_containment_required"
                        | "native_vitest_readonly_containment_required"
                        | "native_package_test_readonly_containment_required"
                        | "native_node_build_output_containment_required"
                )
            ) && result.reason_code == "native_package_review"))
        && result.minimum_action == "review"
        && result.command_extensions.as_ref().is_none_or(|extensions| {
            extensions.binding.uncertainty_count == 0
                && extensions.evaluation_error.is_none()
                && extensions.observations.iter().all(|observation| {
                    contained_test_reason == Some("native_git_readonly_containment_required")
                        && matches!(
                            observation.rule_id.as_str(),
                            "command.git.diff" | "command.git.log" | "command.git.show"
                        )
                        && observation.uncertainty_reasons.is_empty()
                        && observation.effective_segment_indexes == [0]
                })
                && extensions
                    .permission_observations
                    .iter()
                    .all(|observation| {
                        matches!(
                            contained_test_reason,
                            Some(
                                "native_vitest_readonly_containment_required"
                                    | "native_package_test_readonly_containment_required"
                                    | "native_node_tool_readonly_containment_required"
                                    | "native_node_build_output_containment_required"
                            )
                        ) && observation.extension_id == "command.package.node"
                            && observation.permission_id
                                == "command.package.node.permission.package-protection"
                            && observation.uncertainty_reasons.is_empty()
                    })
        })
        && contained_test_reason.is_some()
    {
        result.minimum_action = "sandbox-required".into();
        result.policy_action = "sandbox-required".into();
        result.reason_code = contained_test_reason
            .expect("checked required test profile")
            .into();
        result.reason = concat!(
            "HOL Guard requires protected read-only execution for this repository action. ",
            "Direct execution remains blocked.",
        )
        .into();
    }
    result
}

fn evaluate_signals(
    harness: &str,
    event: &str,
    signals: &GenericSignals,
    command_decision: Option<&Result<PreToolDecisionV1, String>>,
    home_dir: Option<&str>,
    cwd: Option<&str>,
) -> PreToolResultV1 {
    let (mut action_type, mut operation) = infer_action_type(
        event,
        signals.event_hint.as_deref(),
        signals.tool_name.as_deref(),
        signals,
    );
    if action_type == PreToolActionTypeV1::Command
        && command_decision
            .and_then(|decision| decision.as_ref().ok())
            .is_some_and(|decision| package_command(&decision.command_model))
    {
        action_type = PreToolActionTypeV1::Package;
        operation = PreToolOperationV1::Install;
    }
    let benign_prompt = event == "UserPromptSubmit"
        && action_type == PreToolActionTypeV1::Prompt
        && signals.benign_prompt;
    let action = generic_action(
        harness,
        event,
        action_type,
        operation,
        true,
        signals.sensitive_target && !benign_prompt,
    );
    let command_proves_benign = command_decision
        .and_then(|decision| decision.as_ref().ok())
        .is_some_and(|decision| decision.explicitly_benign);
    if !command_proves_benign {
        if let Some(tool) = signals.tool_name.as_deref() {
            if tool_matches(
                tool,
                &["shutdown", "reboot", "wipe", "format", "kill", "terminate"],
            ) {
                return generic_result(
                    action,
                    "block",
                    "native_process_service_dangerous",
                    "HOL Guard blocked a destructive process or service action before execution.",
                );
            }
        }
    }
    if signals.sensitive_target
        && !signals.url_values.is_empty()
        && (!signals.path_values.is_empty() || signals.command.is_some())
    {
        return generic_result(
            action,
            "block",
            "native_secret_exfiltration",
            "HOL Guard blocked a PreToolUse action that combines sensitive data with network transfer.",
        );
    }
    if signals.guard_bypass_intent && action_type == PreToolActionTypeV1::Prompt {
        return generic_result(
            action,
            "block",
            "native_guard_bypass_prompt",
            "HOL Guard blocked this prompt because it asks to disable Guard protection.",
        );
    }
    if signals.exfil_intent && action_type == PreToolActionTypeV1::Prompt {
        let (floor, code) = if action.sensitive_target {
            ("block", "native_prompt_exfiltration_block")
        } else {
            ("require-reapproval", "native_prompt_exfiltration_review")
        };
        return generic_result(
            action,
            floor,
            code,
            "HOL Guard requires review because this prompt asks to transfer data.",
        );
    }
    if signals.destructive_intent && action_type == PreToolActionTypeV1::Prompt {
        let (floor, code) = if action.sensitive_target {
            ("block", "native_prompt_destructive_block")
        } else {
            ("require-reapproval", "native_prompt_destructive_review")
        };
        return generic_result(
            action,
            floor,
            code,
            "HOL Guard requires review because this prompt asks to change local files.",
        );
    }
    if action.sensitive_target && action_type == PreToolActionTypeV1::Prompt {
        // Prompts that request sensitive local data are reviewable: the
        // installed risk policy (local_secret_read) still decides whether a
        // stricter posture turns this floor into a terminal block.
        return generic_result(
            action,
            "require-reapproval",
            "native_sensitive_prompt",
            "HOL Guard requires review because this prompt requests sensitive local data.",
        );
    }
    if signals.prompt_injection_intent && action_type == PreToolActionTypeV1::Prompt {
        return generic_result(
            action,
            "require-reapproval",
            "native_prompt_injection_review",
            "HOL Guard requires review because this prompt asks to override trusted instructions.",
        );
    }
    if signals.subprocess_intent && action_type == PreToolActionTypeV1::Prompt {
        return generic_result(
            action,
            "review",
            "native_prompt_subprocess_review",
            "HOL Guard requires review because this prompt asks to run a subprocess.",
        );
    }
    if benign_prompt {
        return generic_result(
            action,
            "allow",
            "native_prompt_benign",
            "HOL Guard found no guarded prompt intent in this bounded request.",
        );
    }
    if let Some(command_decision) = command_decision {
        let Ok(command_decision) = command_decision else {
            return generic_result(
                action,
                "block",
                "native_pre_tool_malformed_payload",
                "HOL Guard blocked a malformed PreToolUse command before execution.",
            );
        };
        if command_decision.minimum_action == "block" {
            return generic_result(
                action,
                "block",
                &command_decision.reason_code,
                &command_decision.reason,
            );
        }
        if action_type == PreToolActionTypeV1::Command {
            // A benign command proves only its command text. Independent
            // structured paths still describe the action the tool will take.
            if signals.sensitive_target
                && matches!(
                    command_decision.minimum_action.as_str(),
                    "allow" | "warn" | "review"
                )
            {
                return generic_result(
                    action,
                    "review",
                    "native_sensitive_access_review",
                    "HOL Guard requires review before this action can access sensitive local data.",
                );
            }
            return generic_result(
                action,
                &command_decision.minimum_action,
                &command_decision.reason_code,
                &command_decision.reason,
            );
        }
    }
    if action_type == PreToolActionTypeV1::FileRead
        && !signals.sensitive_target
        && signals.url_values.is_empty()
        && signals.path_values.len() == 1
        && super::safe_reads::bounded_file_read_target(&signals.path_values[0], home_dir, cwd)
    {
        return generic_result(
            action,
            "allow",
            "native_exact_safe_file_read",
            "The Rust command authority proved this bounded file read explicitly benign.",
        );
    }
    if action_type == PreToolActionTypeV1::FileWrite
        && signals.tool_name.as_deref().is_some_and(|tool| {
            tool_matches(tool, &["write", "edit", "patch", "replace", "create_file"])
                && !tool_matches(tool, &["delete", "remove", "mkdir"])
        })
        && !signals.sensitive_target
        && signals.url_values.is_empty()
        && signals.command.is_none()
        && signals.path_values.len() == 1
        && super::safe_reads::bounded_file_write_target(&signals.path_values[0], home_dir, cwd)
    {
        return generic_result(
            action,
            "allow",
            "native_exact_safe_file_write",
            "The Rust authority proved this ordinary file write stays inside the verified workspace or a registered worktree of the same repository.",
        );
    }
    let (reason_code, reason) = review_reason(action_type);
    generic_result(action, "review", reason_code, reason)
}
