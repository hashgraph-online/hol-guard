use super::super::PreToolDecisionV1;
use super::extract::GenericSignals;
use super::result::{generic_action, generic_result, review_reason};
use super::tools::{infer_action_type, package_command, tool_matches};
use guard_contracts::{PreToolActionTypeV1, PreToolOperationV1, PreToolResultV1};

pub(super) fn evaluate_signals(
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
        && event == "PreToolUse"
        && harness == "omp"
        && signals.tool_name.as_deref() == Some("read")
        && !signals.sensitive_target
        && signals.url_values.is_empty()
        && signals.command.is_none()
        && signals.path_values.len() == 1
        && super::super::safe_reads::bounded_omp_directory_read_target(
            &signals.path_values[0],
            home_dir,
            cwd,
        )
    {
        return generic_result(
            action,
            "allow",
            "native_exact_safe_directory_read",
            "The Rust command authority proved this bounded directory listing explicitly benign without granting file-content access.",
        );
    }
    if action_type == PreToolActionTypeV1::FileRead
        && event == "PreToolUse"
        && harness == "omp"
        && signals.tool_name.as_deref() == Some("read")
        && !signals.sensitive_target
        && signals.url_values.is_empty()
        && signals.command.is_none()
        && signals.path_values.len() == 1
        && super::super::safe_reads::bounded_omp_file_read_target(
            &signals.path_values[0],
            home_dir,
            cwd,
        )
    {
        return generic_result(
            action,
            "allow",
            "native_exact_safe_file_read",
            "The Rust command authority proved this bounded file read explicitly benign.",
        );
    }
    if action_type == PreToolActionTypeV1::FileRead
        && event == "PreToolUse"
        && harness == "omp"
        && signals.tool_name.as_deref() == Some("read")
        && !signals.sensitive_target
        && signals.url_values.is_empty()
        && signals.command.is_none()
        && signals.path_values.len() == 1
        && super::super::safe_reads::bounded_omp_selector_requires_review(
            &signals.path_values[0],
            home_dir,
            cwd,
        )
    {
        return generic_result(
            action,
            "review",
            "native_unsupported_omp_read_selector",
            "This Oh My Pi read selector is outside the bounded native proof and requires review.",
        );
    }
    if action_type == PreToolActionTypeV1::FileRead
        && !signals.sensitive_target
        && signals.url_values.is_empty()
        && signals.path_values.len() == 1
        && super::super::safe_reads::bounded_file_read_target(
            &signals.path_values[0],
            home_dir,
            cwd,
        )
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
        && super::super::safe_reads::bounded_native_file_write_target(
            &signals.path_values[0],
            home_dir,
            cwd,
        )
    {
        return generic_result(
            action,
            "allow",
            "native_exact_safe_file_write",
            "The Rust authority proved this ordinary file write targets the verified workspace, a registered worktree, or the verified user home and clears sensitive-path checks.",
        );
    }
    let (reason_code, reason) = review_reason(action_type);
    generic_result(action, "review", reason_code, reason)
}
