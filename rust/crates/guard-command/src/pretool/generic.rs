#[path = "generic_evaluate.rs"]
mod evaluate;
use evaluate::evaluate_signals;

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

use super::evaluate_pre_tool_with_context;
use extract::extract_generic_signals;
use result::{generic_action, generic_error_result, generic_result};
use std::time::Instant;

#[path = "agent_metadata.rs"]
mod agent_metadata;

/// Reuse the exact host-input proof after execution; output content still
/// requires its independent native scan and installed policy enforcement.
pub fn bounded_task_metadata_output(payload: &serde_json::Value) -> bool {
    let Some(root) = payload.as_object() else {
        return false;
    };
    let Some(tool) = root.get("tool_name").and_then(serde_json::Value::as_str) else {
        return false;
    };
    if root
        .get("toolName")
        .is_some_and(|alias| alias.as_str() != Some(tool))
    {
        return false;
    }
    let input = root
        .iter()
        .filter(|(key, _)| {
            !matches!(
                key.as_str(),
                "tool_response" | "toolResponse" | "toolResultPreview"
            )
        })
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    agent_metadata::bounded_task_list(&serde_json::Value::Object(input), Some(tool))
}
#[path = "generic_tools.rs"]
mod tools;

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
    evaluate_pre_tool_envelope_with_execution_context(
        harness,
        event,
        payload,
        controls,
        deadline,
        crate::pretool::PathContext { home_dir, cwd },
        None,
    )
}

pub fn evaluate_pre_tool_envelope_with_execution_context(
    harness: &str,
    event: &str,
    payload: &Value,
    controls: Option<&CompiledNativeCommandControls>,
    deadline: Option<Instant>,
    context: super::PathContext<'_>,
    execution_environment: Option<&guard_contracts::GuardExecutionEnvironmentV1>,
) -> PreToolResultV1 {
    let super::PathContext { home_dir, cwd } = context;
    let mut signals = match extract_generic_signals(payload) {
        Ok(value) => value,
        Err(error) => return generic_error_result(harness, event, error),
    };
    let task_metadata = event == "PreToolUse"
        && agent_metadata::bounded_task_list(payload, signals.tool_name.as_deref())
        && signals.command.is_none()
        && !signals.package_present
        && signals.path_values.is_empty()
        && signals.url_values.is_empty();
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
    let mut result = if task_metadata {
        generic_result(
            generic_action(harness, event, PreToolActionTypeV1::Harness,
                if signals.tool_name.as_deref() == Some("TaskOutput") { PreToolOperationV1::Read } else { PreToolOperationV1::Set }, true, false),
            "allow", "native_agent_task_metadata", "The Rust authority verified bounded host task metadata with no new execution or filesystem effects.",
        )
    } else {
        evaluate_signals(
            harness,
            event,
            &signals,
            command_decision.as_ref(),
            home_dir,
            cwd,
        )
    };
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
            super::PathContext { home_dir, cwd },
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
    if event == "PreToolUse"
        // Existing helper-context review may delegate only to enforced
        // read-only containment below; do not replace that protection.
        && result.reason_code != "native_git_helper_context_review"
        && command_model.is_some_and(|model| {
            let destination =
                super::segment_proof::verified_cwd_compound_context(model, super::PathContext { home_dir, cwd });
            let context = super::PathContext { home_dir, cwd: destination.as_deref().or(cwd) };
            let benign = super::segment_proof::benign_command_segments(model, super::PathContext { home_dir, cwd });
            model.segments.iter().enumerate().any(|(index, segment)| {
                segment.executable.as_deref().is_some_and(|executable| {
                    if super::executable_basename(executable) != "git" {
                        return false;
                    }
                    let inspection = super::git_config::execution_free(
                        executable,
                        &segment.arguments,
                        context,
                        deadline,
                        execution_environment,
                    );
                    !segment.environment_names.is_empty()
                        || inspection == Some(false)
                        // Only inspection operations have a configuration proof
                        // to invalidate. Other Git operations retain their own
                        // native review/permission floors, not this read floor.
                        || (inspection.is_some()
                            && index > 0
                            && (0..index).any(|prior| !benign.contains(&prior)))
                })
            })
        })
        && matches!(
            result.minimum_action.as_str(),
            "allow" | "warn" | "review"
        )
    {
        result.minimum_action = "require-reapproval".into();
        result.policy_action = "require-reapproval".into();
        result.decision = "deny".into();
        result.explicitly_benign = false;
        result.reason_code = "native_git_execution_context_review".into();
        result.reason = "HOL Guard requires review because this Git read may execute a configured helper, or its effective configuration could not be verified.".into();
    }
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
