#[path = "generic_extract.rs"]
mod extract;
#[path = "generic_result.rs"]
mod result;

use crate::native_command_controls::CompiledNativeCommandControls;
use crate::{CanonicalCommandV1, CommandModelRequestV1};
use guard_contracts::{PreToolActionTypeV1, PreToolOperationV1, PreToolResultV1};
use serde_json::Value;

use super::{evaluate_pre_tool, PreToolDecisionV1};
use extract::{extract_generic_signals, GenericSignals};
use result::{generic_action, generic_error_result, generic_result, review_reason};
use std::time::Instant;

fn compact(value: &str) -> String {
    value
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

fn tool_tokens(value: &str) -> Vec<String> {
    value
        .split(|character: char| !character.is_ascii_alphanumeric())
        .filter(|token| !token.is_empty())
        .map(|token| token.to_ascii_lowercase())
        .collect()
}

fn tool_matches(tool: &str, terms: &[&str]) -> bool {
    let normalized = compact(tool);
    let tokens = tool_tokens(tool);
    terms.iter().any(|term| {
        let normalized_term = compact(term);
        if normalized == normalized_term {
            return true;
        }
        let term_tokens = tool_tokens(term);
        !term_tokens.is_empty()
            && tokens
                .windows(term_tokens.len())
                .any(|window| window == term_tokens.as_slice())
    })
}

fn is_mcp_tool(tool: &str) -> bool {
    let lowered = tool.to_ascii_lowercase();
    lowered.starts_with("mcp__")
        || lowered.starts_with("mcp_")
        || lowered == "mcp"
        || lowered == "mcptool"
        || lowered == "mcp_tool"
        || lowered.contains("filesystem__")
        || (tool.contains('/') && !tool.starts_with('/'))
}

fn is_package_tool(tool: &str) -> bool {
    tool_matches(
        tool,
        &[
            "npm",
            "pnpm",
            "yarn",
            "bun",
            "pip",
            "pipx",
            "poetry",
            "cargo",
            "gem",
            "brew",
            "apt",
            "dnf",
            "yum",
            "apk",
            "go get",
            "install package",
            "package",
        ],
    )
}

fn is_network_tool(tool: &str) -> bool {
    tool_matches(
        tool,
        &[
            "web_fetch",
            "web_search",
            "fetch_web",
            "http",
            "request",
            "network",
            "open_url",
            "visit_url",
            "download",
        ],
    )
}

fn is_browser_tool(tool: &str) -> bool {
    tool_matches(
        tool,
        &[
            "browser",
            "navigate",
            "click",
            "type",
            "open_page",
            "web_browser",
        ],
    )
}

fn is_process_service_tool(tool: &str) -> bool {
    tool_matches(
        tool,
        &[
            "process",
            "service",
            "systemctl",
            "kill",
            "terminate",
            "start_process",
            "stop_process",
            "restart_process",
            "spawn_process",
        ],
    )
}

fn is_config_tool(tool: &str) -> bool {
    tool_matches(
        tool,
        &["config", "settings", "permission", "policy", "preferences"],
    )
}

fn is_prompt_tool(tool: &str) -> bool {
    tool_matches(
        tool,
        &[
            "spawn_subagent",
            "subagent",
            "prompt",
            "message",
            "ask_user",
        ],
    )
}

fn is_harness_tool(tool: &str) -> bool {
    tool_matches(
        tool,
        &[
            "harness",
            "session_start",
            "session_stop",
            "hook",
            "subagent",
            "agent_context",
        ],
    )
}

fn is_file_write_tool(tool: &str) -> bool {
    tool_matches(
        tool,
        &[
            "write",
            "edit",
            "patch",
            "replace",
            "delete",
            "mkdir",
            "create_file",
        ],
    )
}

fn is_file_read_tool(tool: &str) -> bool {
    tool_matches(
        tool,
        &[
            "read",
            "view",
            "open_file",
            "cat",
            "grep",
            "rg",
            "glob",
            "list_dir",
            "search",
        ],
    )
}

fn is_command_tool(tool: &str) -> bool {
    tool_matches(
        tool,
        &[
            "bash",
            "shell",
            "terminal",
            "run_command",
            "run_commands",
            "run_terminal_command",
            "execute_command",
            "execute_command_line",
        ],
    )
}

fn package_command(model: &CanonicalCommandV1) -> bool {
    model
        .segments
        .iter()
        .any(|segment| segment.executable.as_deref().is_some_and(is_package_tool))
}

fn infer_action_type(
    event: &str,
    event_hint: Option<&str>,
    tool_name: Option<&str>,
    signals: &GenericSignals,
) -> (PreToolActionTypeV1, PreToolOperationV1) {
    let tool = tool_name.unwrap_or_default();
    let event_compact = compact(event_hint.unwrap_or(event));
    if event_compact.contains("userprompt") {
        return (PreToolActionTypeV1::Prompt, PreToolOperationV1::Submit);
    }
    if is_mcp_tool(tool) {
        return (PreToolActionTypeV1::McpTool, PreToolOperationV1::Call);
    }
    if event_compact.contains("beforemcpexecution") {
        return (PreToolActionTypeV1::McpTool, PreToolOperationV1::Call);
    }
    if is_prompt_tool(tool) {
        return (PreToolActionTypeV1::Prompt, PreToolOperationV1::Submit);
    }
    if is_harness_tool(tool) {
        let operation = if tool_matches(tool, &["stop", "end", "close"]) {
            PreToolOperationV1::Stop
        } else {
            PreToolOperationV1::Start
        };
        return (PreToolActionTypeV1::Harness, operation);
    }
    if is_browser_tool(tool) {
        return (PreToolActionTypeV1::Browser, PreToolOperationV1::Navigate);
    }
    if is_package_tool(tool) || signals.package_present {
        return (PreToolActionTypeV1::Package, PreToolOperationV1::Install);
    }
    if is_process_service_tool(tool) {
        let operation = if tool_matches(tool, &["kill", "stop", "terminate", "shutdown"]) {
            PreToolOperationV1::Stop
        } else {
            PreToolOperationV1::Start
        };
        return (PreToolActionTypeV1::ProcessService, operation);
    }
    if is_config_tool(tool) {
        return (PreToolActionTypeV1::Config, PreToolOperationV1::Set);
    }
    if is_file_write_tool(tool) {
        return (PreToolActionTypeV1::FileWrite, PreToolOperationV1::Write);
    }
    if is_file_read_tool(tool) {
        return (PreToolActionTypeV1::FileRead, PreToolOperationV1::Read);
    }
    if signals.prompt_present {
        return (PreToolActionTypeV1::Prompt, PreToolOperationV1::Submit);
    }
    if is_network_tool(tool) || !signals.url_values.is_empty() {
        return (PreToolActionTypeV1::Network, PreToolOperationV1::Request);
    }
    if signals.command.is_some() && (tool.is_empty() || is_command_tool(tool)) {
        return (PreToolActionTypeV1::Command, PreToolOperationV1::Execute);
    }
    if event_compact.contains("beforeshellexecution") {
        return (PreToolActionTypeV1::Command, PreToolOperationV1::Execute);
    }
    if event_compact.contains("beforereadfile") {
        return (PreToolActionTypeV1::FileRead, PreToolOperationV1::Read);
    }
    if event_compact.contains("beforewritefile") {
        return (PreToolActionTypeV1::FileWrite, PreToolOperationV1::Write);
    }
    if !signals.path_values.is_empty() {
        return (PreToolActionTypeV1::FileRead, PreToolOperationV1::Read);
    }
    if signals.command.is_some() && tool.is_empty() {
        return (PreToolActionTypeV1::Command, PreToolOperationV1::Execute);
    }
    if event_compact.contains("session")
        || event_compact.contains("harness")
        || event_compact.contains("subagent")
    {
        return (PreToolActionTypeV1::Harness, PreToolOperationV1::Start);
    }
    (PreToolActionTypeV1::Unknown, PreToolOperationV1::Unknown)
}

/// Evaluate the complete raw PreToolUse payload in native code.
///
/// This remains separate from `evaluate_pre_tool`, the compatibility
/// command-model operation used by older clients.
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
    let signals = match extract_generic_signals(payload) {
        Ok(value) => value,
        Err(error) => return generic_error_result(harness, event, error),
    };
    let command_decision = signals.command.as_deref().map(|command| {
        evaluate_pre_tool(&CommandModelRequestV1 {
            command: command.to_owned(),
            dialect: "posix".to_owned(),
            transport: "shell_string".to_owned(),
            extraction_provenance: "pre-tool-generic".to_owned(),
        })
    });
    let result = evaluate_signals(harness, event, &signals, command_decision.as_ref());
    match (controls, command_decision) {
        (Some(controls), Some(Ok(decision))) => controls.apply_with_tool(
            Some(&decision.command_model),
            result,
            signals.tool_name.as_deref(),
            &signals.package_values,
            deadline,
        ),
        (Some(controls), _) => controls.apply_with_tool(
            None,
            result,
            signals.tool_name.as_deref(),
            &signals.package_values,
            deadline,
        ),
        _ => result,
    }
}

fn evaluate_signals(
    harness: &str,
    event: &str,
    signals: &GenericSignals,
    command_decision: Option<&Result<PreToolDecisionV1, String>>,
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
    let action = generic_action(
        harness,
        event,
        action_type,
        operation,
        true,
        signals.sensitive_target,
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
    if signals.sensitive_target && action_type == PreToolActionTypeV1::Prompt {
        return generic_result(
            action,
            "block",
            "native_sensitive_prompt",
            "HOL Guard blocked a prompt that requests sensitive local data before execution.",
        );
    }
    if let Some(command_decision) = command_decision {
        let command_decision = match command_decision {
            Ok(value) => value,
            Err(_) => {
                return generic_result(
                    action,
                    "block",
                    "native_pre_tool_malformed_payload",
                    "HOL Guard blocked a malformed PreToolUse command before execution.",
                )
            }
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
    let (reason_code, reason) = review_reason(action_type);
    generic_result(action, "review", reason_code, reason)
}
