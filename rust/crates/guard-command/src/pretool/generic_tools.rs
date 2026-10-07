use super::{PreToolActionTypeV1, PreToolOperationV1};
use crate::pretool::generic::extract::GenericSignals;
use crate::CanonicalCommandV1;

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

pub(super) fn tool_matches(tool: &str, terms: &[&str]) -> bool {
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
    // tool_matches also recognizes namespaced forms such as functions.exec_command.
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
            "exec_command",
            "execute_command_line",
            "exec",
        ],
    )
}

pub(super) fn package_command(model: &CanonicalCommandV1) -> bool {
    model
        .segments
        .iter()
        .any(|segment| segment.executable.as_deref().is_some_and(is_package_tool))
}

pub(super) fn infer_action_type(
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
