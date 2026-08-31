use guard_contracts::PreToolActionTypeV1;
use serde_json::{Map, Value};

use super::bounded_selector_value;

pub(crate) fn preferred_tool_name(maps: &[&Map<String, Value>]) -> Result<Option<String>, String> {
    for keys in [
        &["tool_name", "toolName", "toolname", "tool"][..],
        &["name"][..],
    ] {
        let mut selected: Option<String> = None;
        for record in maps {
            for key in keys {
                let Some(value) = record.get(*key) else {
                    continue;
                };
                let Some(value) = value.as_str() else {
                    continue;
                };
                let value = bounded_selector_value(value)?;
                if selected
                    .as_deref()
                    .is_some_and(|previous| previous != value)
                {
                    return Err("native_policy_tool_selector_conflict".to_owned());
                }
                selected = Some(value);
            }
        }
        if selected.is_some() {
            return Ok(selected);
        }
    }
    Ok(None)
}

pub(crate) fn tool_matches(tool: &str, terms: &[&str]) -> bool {
    let normalized: String = tool
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect();
    let tokens: Vec<String> = tool
        .split(|character: char| !character.is_ascii_alphanumeric())
        .filter(|token| !token.is_empty())
        .map(|token| token.to_ascii_lowercase())
        .collect();
    terms.iter().any(|term| {
        let normalized_term: String = term
            .chars()
            .filter(|character| character.is_ascii_alphanumeric())
            .flat_map(char::to_lowercase)
            .collect();
        if normalized == normalized_term {
            return true;
        }
        let term_tokens: Vec<String> = term
            .split(|character: char| !character.is_ascii_alphanumeric())
            .filter(|token| !token.is_empty())
            .map(|token| token.to_ascii_lowercase())
            .collect();
        !term_tokens.is_empty()
            && tokens
                .windows(term_tokens.len())
                .any(|window| window == term_tokens.as_slice())
    })
}

pub(crate) fn classify_tool_name(tool: &str) -> PreToolActionTypeV1 {
    let lowered = tool.to_ascii_lowercase();
    if lowered.starts_with("mcp__")
        || lowered.starts_with("mcp_")
        || lowered == "mcp"
        || lowered.contains("filesystem__")
    {
        PreToolActionTypeV1::McpTool
    } else if tool_matches(
        tool,
        &[
            "npm", "pnpm", "yarn", "bun", "pip", "cargo", "package", "install",
        ],
    ) {
        PreToolActionTypeV1::Package
    } else if tool_matches(
        tool,
        &[
            "process",
            "service",
            "systemctl",
            "kill",
            "terminate",
            "start_process",
            "stop_process",
        ],
    ) {
        PreToolActionTypeV1::ProcessService
    } else if tool_matches(tool, &["config", "settings", "permission", "policy"]) {
        PreToolActionTypeV1::Config
    } else if tool_matches(tool, &["prompt", "message", "ask_user", "subagent"]) {
        PreToolActionTypeV1::Prompt
    } else if tool_matches(tool, &["harness", "session_start", "session_stop", "hook"]) {
        PreToolActionTypeV1::Harness
    } else if tool_matches(tool, &["browser", "navigate", "click", "open_page"]) {
        PreToolActionTypeV1::Browser
    } else if tool_matches(
        tool,
        &["write", "edit", "patch", "replace", "delete", "mkdir"],
    ) {
        PreToolActionTypeV1::FileWrite
    } else if tool_matches(
        tool,
        &["read", "view", "open_file", "cat", "grep", "rg", "glob"],
    ) {
        PreToolActionTypeV1::FileRead
    } else if tool_matches(
        tool,
        &[
            "web_fetch",
            "web_search",
            "fetch_web",
            "http",
            "request",
            "network",
            "open_url",
            "download",
        ],
    ) {
        PreToolActionTypeV1::Network
    } else if tool_matches(
        tool,
        &[
            "bash",
            "shell",
            "terminal",
            "run_command",
            "execute_command",
        ],
    ) {
        PreToolActionTypeV1::Command
    } else {
        PreToolActionTypeV1::Unknown
    }
}

pub(crate) fn risk_classes(
    action_type: PreToolActionTypeV1,
    sensitive_target: bool,
    reason_code: &str,
) -> Vec<&'static str> {
    let mut risks = Vec::new();
    if sensitive_target {
        risks.push("local_secret_read");
    }
    match action_type {
        PreToolActionTypeV1::Command => risks.push("execution"),
        PreToolActionTypeV1::FileRead => {}
        PreToolActionTypeV1::FileWrite => risks.push("persistence"),
        PreToolActionTypeV1::Package => risks.push("package_script"),
        PreToolActionTypeV1::McpTool => risks.push("mcp_dangerous_tool"),
        PreToolActionTypeV1::Network => risks.push("network_egress"),
        PreToolActionTypeV1::ProcessService => risks.push("persistence"),
        PreToolActionTypeV1::Browser => risks.push("network_egress"),
        PreToolActionTypeV1::Config => risks.push("guard_bypass"),
        PreToolActionTypeV1::Prompt => risks.push("prompt_injection"),
        PreToolActionTypeV1::Harness => risks.push("execution"),
        PreToolActionTypeV1::Unknown => {}
    }
    if reason_code.contains("destructive") {
        risks.push("destructive_shell");
    }
    if reason_code.contains("exfiltration") {
        risks.push("credential_exfiltration");
        risks.push("data_flow_exfiltration");
    }
    if reason_code.contains("network") {
        risks.push("network_egress");
    }
    risks.sort_unstable();
    risks.dedup();
    risks
}
