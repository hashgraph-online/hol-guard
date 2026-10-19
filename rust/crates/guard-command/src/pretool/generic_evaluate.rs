use super::super::PreToolDecisionV1;
use super::extract::GenericSignals;
use super::result::{generic_action, generic_result, review_reason};
use super::tools::{
    infer_action_type, is_package_tool, package_command, tool_matches, tool_name_is_typed,
};
use guard_contracts::{PreToolActionTypeV1, PreToolOperationV1, PreToolResultV1};

#[path = "generic_build_review.rs"]
mod build_review;

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
    // A command the Rust authority proved explicitly benign (a lone version
    // query, say) keeps its command decision even when it names a package tool.
    if action_type == PreToolActionTypeV1::Command
        && command_decision
            .and_then(|decision| decision.as_ref().ok())
            .is_some_and(|decision| {
                !decision.explicitly_benign && package_command(&decision.command_model)
            })
    {
        action_type = PreToolActionTypeV1::Package;
        operation = PreToolOperationV1::Install;
    }
    // One of Oh My Pi's `github` lookups is a request to GitHub, not an
    // unrecognized tool.
    let github_read = super::github::proven_read(signals);
    if github_read {
        (action_type, operation) = (PreToolActionTypeV1::Network, PreToolOperationV1::Request);
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
    // These five gates read the prompt text itself. They cover exactly what a
    // prompt-typed action used to carry: an inline prompt, and a tool whose
    // name Guard does not recognize, which no longer types as a prompt just
    // because it has a `query`. A tool matched by name keeps the proofs its
    // own type carries, so it reaches these gates no more often than before.
    // A proven `github` lookup is typed like any other network request: its
    // `query` is search syntax sent to GitHub, never an instruction to a model.
    let prompt_text = signals.prompt_present
        && !github_read
        && (action_type == PreToolActionTypeV1::Prompt
            || !tool_name_is_typed(signals.tool_name.as_deref().unwrap_or_default()));
    // A prompt is never queued for approval, so its reason says so. The same
    // sentence on a tool call would contradict the row that call raises.
    let as_prompt = action_type == PreToolActionTypeV1::Prompt;
    let reason = |prompt: &'static str, tool: &'static str| if as_prompt { prompt } else { tool };
    if signals.guard_bypass_intent && prompt_text {
        return generic_result(
            action,
            "block",
            "native_guard_bypass_prompt",
            reason(
                "HOL Guard blocked this prompt because it asks to disable Guard protection.",
                "HOL Guard blocked this tool call because its text asks to disable Guard protection.",
            ),
        );
    }
    if signals.exfil_intent && prompt_text {
        let (floor, code) = if action.sensitive_target {
            ("block", "native_prompt_exfiltration_block")
        } else {
            ("require-reapproval", "native_prompt_exfiltration_review")
        };
        return generic_result(
            action,
            floor,
            code,
            reason(
                "HOL Guard did not send this prompt because it asks to send data to an external place. Nothing is waiting for approval; rephrase that part of the request.",
                "HOL Guard held this tool call because its text asks to send data to an external place.",
            ),
        );
    }
    if signals.destructive_intent && prompt_text {
        let (floor, code) = if action.sensitive_target {
            ("block", "native_prompt_destructive_block")
        } else {
            ("require-reapproval", "native_prompt_destructive_review")
        };
        return generic_result(
            action,
            floor,
            code,
            reason(
                "HOL Guard did not send this prompt because it asks to delete or overwrite local files. Nothing is waiting for approval; rephrase that part, or run the change yourself.",
                "HOL Guard held this tool call because its text asks to delete or overwrite local files.",
            ),
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
            "HOL Guard did not send this prompt because it asks to read credentials or other sensitive local data. Nothing is waiting for approval; rephrase that part of the request.",
        );
    }
    if signals.prompt_injection_intent && prompt_text {
        return generic_result(
            action,
            "require-reapproval",
            "native_prompt_injection_review",
            reason(
                "HOL Guard did not send this prompt because it asks to override trusted instructions. Nothing is waiting for approval; rephrase that part of the request.",
                "HOL Guard held this tool call because its text asks to override trusted instructions.",
            ),
        );
    }
    if signals.subprocess_intent && prompt_text {
        return generic_result(
            action,
            "review",
            "native_prompt_subprocess_review",
            reason(
                "HOL Guard did not send this prompt because it asks to run a subprocess. Nothing is waiting for approval; rephrase that part of the request.",
                "HOL Guard held this tool call because its text asks to run a subprocess.",
            ),
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
        && super::omp::host_reference_reason(&signals.path_values[0]).is_some()
    {
        return generic_result(
            action,
            "allow",
            super::omp::host_reference_reason(&signals.path_values[0]).unwrap_or_default(),
            "This Oh My Pi artifact or skill reference names host-held content, not a filesystem path.",
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
    // A read that names its targets and names none of them opens no file, so
    // there is nothing to prove safe and nothing to protect. Cline's install
    // canary sends exactly this shape, and reviewing it asks the user to
    // approve a call that reads nothing. Only a tool that opens the files it
    // is handed qualifies: a search or listing tool reads a default location
    // when it is handed no target, so naming none of them is not reading none.
    if action_type == PreToolActionTypeV1::FileRead
        && signals.empty_read_request
        && signals
            .tool_name
            .as_deref()
            .is_some_and(opens_only_named_files)
        && !signals.sensitive_target
        && signals.url_values.is_empty()
        && signals.command.is_none()
    {
        return generic_result(
            action,
            "allow",
            "native_empty_file_read_request",
            "This read names no file to open, so it reads nothing.",
        );
    }
    if action_type == PreToolActionTypeV1::FileRead
        && !signals.sensitive_target
        && signals.url_values.is_empty()
        && signals.path_values.len() == 1
        && if matches!(signals.tool_name.as_deref(), Some("Read" | "read")) {
            // Only the host `Read` tools open their path literally, so a
            // `[slug]` directory is a name. Any other tool may glob-expand.
            super::super::safe_reads::bounded_structured_file_read_target(
                &signals.path_values[0],
                home_dir,
                cwd,
            )
        } else {
            super::super::safe_reads::bounded_file_read_target(
                &signals.path_values[0],
                home_dir,
                cwd,
            )
        }
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
            tool_matches(
                tool,
                &[
                    "write",
                    "edit",
                    "multiedit",
                    "patch",
                    "replace",
                    "create_file",
                ],
            ) && !tool_matches(tool, &["delete", "remove", "mkdir"])
        })
        && !signals.sensitive_target
        && signals.url_values.is_empty()
        && signals.command.is_none()
        && signals.path_values.len() == 1
        && (if matches!(
            signals.tool_name.as_deref(),
            Some("Write" | "Edit" | "MultiEdit" | "write" | "edit")
        ) {
            // Only the host file tools open their path literally, so an `[id]`
            // route directory or a `$postId` route file is a name. Any other
            // tool may glob-expand or substitute.
            super::super::safe_reads::bounded_structured_file_write_target(
                &signals.path_values[0],
                home_dir,
                cwd,
            )
        } else {
            super::super::safe_reads::bounded_native_file_write_target(
                &signals.path_values[0],
                home_dir,
                cwd,
            )
        } || super::super::safe_writes::bounded_native_temporary_write_target(
            &signals.path_values[0],
            home_dir,
            cwd,
        ))
    {
        return generic_result(
            action,
            "allow",
            "native_exact_safe_file_write",
            "The Rust authority proved this ordinary file write targets the verified workspace, a registered worktree, the verified user home, or a private user-owned temporary directory and clears sensitive-path checks.",
        );
    }
    if github_read {
        // The installed new_network_domain_action floor decides whether the
        // lookup runs, as it does for a plain web fetch.
        return generic_result(
            action,
            "allow",
            "native_github_read",
            "The Rust authority proved this Oh My Pi github call is one of the tool's read-only lookups; the installed network setting decides the outcome.",
        );
    }
    if action_type == PreToolActionTypeV1::Network
        && super::web_fetch::plain_public_web_request(signals)
    {
        // A plain public GET is low risk by itself; the installed
        // new_network_domain_action floor decides whether it runs.
        return generic_result(
            action,
            "allow",
            "native_plain_web_request",
            "The Rust authority proved this web fetch or search is a plain request for public web content; the installed network setting decides the outcome.",
        );
    }
    if action_type == PreToolActionTypeV1::FileRead
        && event == "PreToolUse"
        && matches!(signals.tool_name.as_deref(), Some("Read" | "read"))
        && !signals.sensitive_target
        && signals.url_values.is_empty()
        && signals.command.is_none()
        && signals.path_values.len() == 1
        && super::super::safe_reads::missing_read_target(
            &signals.path_values[0],
            home_dir,
            cwd,
            harness == "omp",
        )
    {
        // Nothing exists to read, so stopping the call costs nothing. Saying
        // why lets the agent fix the path instead of waiting on an approval.
        let mut result = generic_result(action, "block", MISSING_PATH, "");
        result.reason = missing_path_reason(
            "HOL Guard did not run this read because the path does not exist. Check the path, for example by listing its parent directory, and try again with the correct one.",
            "read",
            Some(&signals.path_values[0]),
        );
        return result;
    }
    let (reason_code, mut reason) = review_reason(action_type);
    if action_type == PreToolActionTypeV1::Unknown
        && matches!(harness, "omp" | "pi")
        && signals.tool_name.as_deref() == Some("eval")
    {
        // Same review; the reason names the form Guard can check instead.
        reason = EVAL_REVIEW_REASON;
    }
    if action_type == PreToolActionTypeV1::Package
        && command_decision
            .and_then(|decision| decision.as_ref().ok())
            .is_some_and(|decision| {
                build_review::build_or_test_command(&decision.command_model, is_package_tool)
            })
    {
        // Same package review; install advice does not fit a build or test.
        reason = build_review::BUILD_REVIEW_REASON;
    }
    generic_result(action, "review", reason_code, reason)
}

const EVAL_REVIEW_REASON: &str = "HOL Guard requires review because code run by eval can start processes, change files or reach the network, and Guard cannot check what it will do before it runs. Run shell commands with the bash tool instead, where Guard checks each command.";

pub(super) const MISSING_PATH: &str = "native_missing_path";

/// Why a call that names a missing path did not run. It names the path when
/// the path prints safely, and says where a relative one is read from:
/// agents that ran commands in another folder retry the same relative path.
/// Otherwise it keeps `fallback`.
pub(super) fn missing_path_reason(fallback: &str, action: &str, path: Option<&str>) -> String {
    let Some(path) = path.filter(|path| {
        !path.is_empty()
            && path.chars().count() <= 512
            && !path.contains(|c: char| c.is_control() || c == '`')
    }) else {
        return fallback.to_owned();
    };
    format!(
        "HOL Guard did not run this {action} because `{path}` does not exist.{} Check the path, for example by listing its parent directory, and try again with the correct one.",
        if path.starts_with(['/', '~']) {
            ""
        } else {
            " A relative path is read from the session folder, not from the folder of an earlier command."
        }
    )
}

/// Whether the tool opens the files it is handed and nothing else. `grep`,
/// `glob` and the listing tools are file reads too, but they fall back to a
/// default location, and their real target can sit under a key the generic
/// extractor does not read.
fn opens_only_named_files(tool: &str) -> bool {
    tool_matches(tool, &["read", "view", "open_file", "cat"])
        && !tool_matches(
            tool,
            &["grep", "rg", "glob", "search", "list_dir", "find", "ls"],
        )
}
