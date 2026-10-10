//! Typed action envelope for one harness hook payload (`runtime/actions.py`
//! `normalize_harness_payload`).

use std::path::Path;

use sha2::{Digest, Sha256};

use crate::hook_adapter_envelope_text::{
    action_type, command_text_from_tool_payload, cursor_tool_input_urls, hook_event_name, hosts_in,
    is_shell_tool, mcp_details, network_hosts, payload_with_default_event, prompt_value,
    raw_target_paths, tool_call_from_payload, tool_input_from_payload, tool_name_from_payload,
    CURSOR_NETWORK_TOOL_NAMES,
};
use crate::hook_adapter_paths::{
    redacted_target_path, workspace_hash_text, workspace_label as label_for, PathEnv, PurePath,
};
use crate::hook_adapter_prepare::{prepare_payload, string_value, AdapterError};
use crate::hook_adapter_prepare_cline::is_cline_network_tool;
use crate::hook_adapter_pytext::{
    dedupe_preserving_order, py_collapse_whitespace, py_lower, py_prefix_chars, py_strip,
};
use crate::hook_adapter_redact::{command_detail, redacted_payload};
use crate::hook_adapter_value::{string_list, OMap, OValue};
use crate::redacted_command_tokens::redact_text;
use crate::shell_command_wrappers::normalize_transparent_shell_command;

const PROMPT_EXCERPT_LIMIT: usize = 240;
const GROK_FILE_READ_TOOLS: &[&str] = &[
    "grep",
    "glob",
    "list_dir",
    "listdir",
    "list_directory",
    "read",
];

/// Package intent facts the envelope records.
#[derive(Debug, Clone, PartialEq)]
pub struct IntentSummary {
    pub package_manager: String,
    pub intent_kind: String,
    /// `(raw_spec, package_name)` per target, in order.
    pub targets: Vec<(String, Option<String>)>,
}

/// Resolves package intent for a normalized command. `None` is "no intent".
pub type IntentProvider<'a> =
    dyn FnMut(&str, Option<&Path>, Option<&Path>) -> Option<IntentSummary> + 'a;

pub struct EnvelopeRequest<'a> {
    pub harness: &'a str,
    pub event_name: &'a str,
    pub payload: &'a OMap,
    pub workspace: Option<&'a str>,
    pub home_dir: Option<&'a str>,
    pub devin_project_dir: Option<&'a str>,
    pub env: PathEnv,
}

/// Alias table of `_ACTION_PAYLOAD_NORMALIZERS`, plus the Cline aliases.
pub fn canonical_harness(harness: &str) -> Option<&'static str> {
    Some(match py_lower(py_strip(harness)).as_str() {
        "codex" => "codex",
        "claude" | "claude-code" => "claude-code",
        "opencode" => "opencode",
        "copilot" => "copilot",
        "gemini" => "gemini",
        "hermes" => "hermes",
        "openclaw" => "openclaw",
        "cursor" => "cursor",
        "grok" => "grok",
        "kimi" => "kimi",
        "pi" => "pi",
        "omp" => "omp",
        "zcode" | "zai" => "zcode",
        "devin" | "devin-cli" | "cognition-devin" => "devin",
        "cline" | "cline-cli" | "cline-vscode" => "cline",
        _ => return None,
    })
}

fn opt(value: Option<&str>) -> OValue {
    value.map_or(OValue::Null, OValue::str)
}

/// The envelope fields the identity hash covers.
struct Envelope {
    harness: String,
    event_name: String,
    action_type: String,
    workspace: Option<String>,
    workspace_hash: Option<String>,
    tool_name: Option<String>,
    command: Option<String>,
    prompt_excerpt: Option<String>,
    prompt_text: Option<String>,
    target_paths: Vec<String>,
    network_hosts: Vec<String>,
    mcp_server: Option<String>,
    mcp_tool: Option<String>,
    package_manager: Option<String>,
    package_name: Option<String>,
    package_intent_kind: Option<String>,
    package_targets: Vec<String>,
    raw_payload_redacted: OMap,
    action_id: String,
}

impl Envelope {
    fn compute_action_id(&self) -> String {
        let mut payload = OMap::new();
        payload.insert("schema_version", OValue::Int("1".to_owned()));
        payload.insert("harness", OValue::str(self.harness.as_str()));
        payload.insert("event_name", OValue::str(self.event_name.as_str()));
        payload.insert("action_type", OValue::str(self.action_type.as_str()));
        payload.insert("workspace_hash", opt(self.workspace_hash.as_deref()));
        payload.insert("tool_name", opt(self.tool_name.as_deref()));
        payload.insert("command", opt(self.command.as_deref().map(py_strip)));
        payload.insert("prompt_excerpt", opt(self.prompt_excerpt.as_deref()));
        payload.insert("target_paths", string_list(&self.target_paths));
        payload.insert("network_hosts", string_list(&self.network_hosts));
        payload.insert("mcp_server", opt(self.mcp_server.as_deref()));
        payload.insert("mcp_tool", opt(self.mcp_tool.as_deref()));
        payload.insert("package_manager", OValue::Null);
        payload.insert("package_name", OValue::Null);
        payload.insert("script_name", OValue::Null);
        let digest = Sha256::digest(OValue::Map(payload).canonical_json().as_bytes());
        hex::encode(digest)
    }

    fn into_map(self) -> OMap {
        let mut map = OMap::new();
        map.insert("schema_version", OValue::Int("1".to_owned()));
        map.insert("action_id", OValue::Str(self.action_id));
        map.insert("harness", OValue::Str(self.harness));
        map.insert("event_name", OValue::Str(self.event_name));
        map.insert("action_type", OValue::Str(self.action_type));
        map.insert("workspace", opt(self.workspace.as_deref()));
        map.insert("workspace_hash", opt(self.workspace_hash.as_deref()));
        map.insert("tool_name", opt(self.tool_name.as_deref()));
        map.insert("command", opt(self.command.as_deref()));
        map.insert("prompt_excerpt", opt(self.prompt_excerpt.as_deref()));
        map.insert("prompt_text", opt(self.prompt_text.as_deref()));
        map.insert("target_paths", string_list(&self.target_paths));
        map.insert("network_hosts", string_list(&self.network_hosts));
        map.insert("mcp_server", opt(self.mcp_server.as_deref()));
        map.insert("mcp_tool", opt(self.mcp_tool.as_deref()));
        map.insert("package_manager", opt(self.package_manager.as_deref()));
        map.insert("package_name", opt(self.package_name.as_deref()));
        map.insert("command_category", OValue::Null);
        map.insert(
            "package_intent_kind",
            opt(self.package_intent_kind.as_deref()),
        );
        map.insert("package_targets", string_list(&self.package_targets));
        map.insert("pre_execution_result", OValue::Null);
        map.insert("script_name", OValue::Null);
        map.insert(
            "raw_payload_redacted",
            OValue::Map(self.raw_payload_redacted),
        );
        map
    }
}

fn prompt_text(value: Option<&str>) -> Option<String> {
    let redacted = redact_text(py_strip(value?)).text;
    let collapsed = py_collapse_whitespace(&redacted);
    (!collapsed.is_empty()).then_some(collapsed)
}

fn path_text(text: Option<&str>) -> Option<String> {
    text.map(|text| PurePath::host(text).text())
}

fn normalize_action_payload(
    request: &EnvelopeRequest<'_>,
    harness: &str,
    payload: &OMap,
    provider: &mut IntentProvider<'_>,
) -> Result<Envelope, AdapterError> {
    let env = &request.env;
    let home_dir = path_text(request.home_dir);
    let workspace = path_text(request.workspace);
    let mut normalized_payload = payload.clone();
    let event_name = hook_event_name(&normalized_payload);
    let explicit_tool = tool_name_from_payload(&normalized_payload);
    let (call_name, call_input) = tool_call_from_payload(
        normalized_payload.get("toolCalls"),
        explicit_tool.as_deref(),
    )?;
    let tool_name = explicit_tool.or(call_name);
    let mut tool_input = tool_input_from_payload(&normalized_payload)?;
    if tool_input.is_empty() {
        if let Some(call_input) = call_input {
            tool_input = call_input;
        }
    }
    let raw_command = command_text_from_tool_payload(tool_name.as_deref(), &tool_input);
    let (normalized_command, wrapper_chain) = match &raw_command {
        None => (None, Vec::new()),
        Some(command) if !is_shell_tool(tool_name.as_deref()) => {
            (Some(command.clone()), Vec::new())
        }
        Some(command) => {
            let normalized = normalize_transparent_shell_command(
                command,
                workspace.as_deref().map(Path::new),
                home_dir.as_deref().map(Path::new),
            );
            (
                Some(normalized.normalized_command),
                normalized.wrapper_chain,
            )
        }
    };
    if !wrapper_chain.is_empty() {
        let mut wrapped = tool_input.clone();
        wrapped.insert(
            "guard_inner_command",
            normalized_command
                .as_deref()
                .map_or(OValue::Null, OValue::str),
        );
        wrapped.insert("guard_shell_wrappers", string_list(&wrapper_chain));
        normalized_payload.insert("tool_input", OValue::Map(wrapped));
    }
    let command = match &normalized_command {
        Some(text) => Some(command_detail(text, home_dir.as_deref(), env)?),
        None => None,
    };
    let prompt = prompt_text(prompt_value(&normalized_payload).as_deref());
    let prompt_excerpt = prompt
        .as_deref()
        .map(|text| py_prefix_chars(text, PROMPT_EXCERPT_LIMIT).to_owned());
    let (mcp_server, mcp_tool) = mcp_details(&normalized_payload, tool_name.as_deref());
    let action = action_type(
        &event_name,
        tool_name.as_deref(),
        normalized_command.as_deref(),
        prompt_excerpt.as_deref(),
        mcp_server.as_deref(),
    );
    let mut target_paths = Vec::new();
    for path in raw_target_paths(
        tool_name.as_deref(),
        &tool_input,
        normalized_command.as_deref(),
        prompt.as_deref(),
    )? {
        if let Some(redacted) = redacted_target_path(&path, home_dir.as_deref(), env)? {
            target_paths.push(redacted);
        }
    }
    let target_paths = dedupe_preserving_order(target_paths);
    let hosts = network_hosts(raw_command.as_deref(), prompt.as_deref())?;
    let workspace_label = match workspace.as_deref() {
        Some(text) => Some(label_for(text, home_dir.as_deref(), env)?),
        None => None,
    };
    let workspace_hash = match workspace.as_deref() {
        Some(text) => Some(hex::encode(Sha256::digest(
            workspace_hash_text(text, env)?.as_bytes(),
        ))),
        None => None,
    };
    let intent = normalized_command
        .as_deref()
        .filter(|command| !command.is_empty())
        .and_then(|command| {
            provider(
                command,
                workspace.as_deref().map(Path::new),
                home_dir.as_deref().map(Path::new),
            )
        });
    let (package_manager, package_intent_kind, package_targets, package_name) = match intent {
        Some(intent) => {
            let targets = intent
                .targets
                .iter()
                .filter(|(spec, _)| !spec.is_empty())
                .map(|(spec, _)| spec.clone())
                .collect();
            let name = intent
                .targets
                .iter()
                .find_map(|(_, name)| name.clone().filter(|name| !name.is_empty()));
            (
                Some(intent.package_manager),
                Some(intent.intent_kind),
                targets,
                name,
            )
        }
        None => (None, None, Vec::new(), None),
    };
    let raw_payload_redacted = redacted_payload(&normalized_payload, home_dir.as_deref(), env)?;
    let mut envelope = Envelope {
        harness: harness.to_owned(),
        event_name,
        action_type: action.to_owned(),
        workspace: workspace_label,
        workspace_hash,
        tool_name,
        command,
        prompt_excerpt,
        prompt_text: prompt,
        target_paths,
        network_hosts: hosts,
        mcp_server,
        mcp_tool,
        package_manager,
        package_name,
        package_intent_kind,
        package_targets,
        raw_payload_redacted,
        action_id: String::new(),
    };
    envelope.action_id = envelope.compute_action_id();
    Ok(envelope)
}

fn adjust_cursor(envelope: &mut Envelope, prepared: &OMap) -> Result<(), AdapterError> {
    if envelope.event_name != "PreToolUse" {
        return Ok(());
    }
    let tool = py_lower(py_strip(envelope.tool_name.as_deref().unwrap_or("")));
    if !CURSOR_NETWORK_TOOL_NAMES.contains(&tool.as_str()) {
        return Ok(());
    }
    let urls = cursor_tool_input_urls(prepared.get("tool_input"));
    let texts: Vec<&str> = urls.iter().map(String::as_str).collect();
    envelope.network_hosts = hosts_in(&texts)?;
    "network_request".clone_into(&mut envelope.action_type);
    envelope.action_id = envelope.compute_action_id();
    Ok(())
}

fn adjust_grok(envelope: &mut Envelope) {
    if matches!(
        envelope.event_name.as_str(),
        "SessionStart" | "SubagentStart"
    ) {
        "config_change".clone_into(&mut envelope.action_type);
        return;
    }
    if envelope.event_name != "PreToolUse" {
        return;
    }
    let tool = py_lower(envelope.tool_name.as_deref().unwrap_or(""));
    if matches!(tool.as_str(), "task" | "spawn_subagent") {
        "prompt".clone_into(&mut envelope.action_type);
    } else if GROK_FILE_READ_TOOLS.contains(&tool.as_str()) {
        "file_read".clone_into(&mut envelope.action_type);
    }
}

fn adjust_cline(envelope: &mut Envelope, prepared: &OMap) {
    let original = prepared
        .get("tool_input")
        .and_then(OValue::as_map)
        .and_then(|input| string_value(input.get("cline_tool_name")));
    if original.is_some_and(|name| is_cline_network_tool(&name)) {
        "network_request".clone_into(&mut envelope.action_type);
    }
}

/// `normalize_harness_payload`, returned as the ordered `to_dict()` map.
pub fn normalize_harness_envelope(
    request: &EnvelopeRequest<'_>,
    provider: &mut IntentProvider<'_>,
) -> Result<OMap, AdapterError> {
    let Some(canonical) = canonical_harness(request.harness) else {
        return Err(AdapterError::UnsupportedHarness(request.harness.to_owned()));
    };
    let payload = payload_with_default_event(request.payload, request.event_name);
    let prepared = prepare_payload(canonical, &payload, request.devin_project_dir)?;
    let mut envelope = normalize_action_payload(request, canonical, &prepared, provider)?;
    match canonical {
        "cursor" => adjust_cursor(&mut envelope, &prepared)?,
        "grok" => adjust_grok(&mut envelope),
        "cline" => adjust_cline(&mut envelope, &prepared),
        _ => {}
    }
    Ok(envelope.into_map())
}

/// `_command_detail` for a present command.
pub fn command_detail_text(
    text: &str,
    home_dir: Option<&str>,
    env: &PathEnv,
) -> Result<String, AdapterError> {
    command_detail(text, home_dir, env)
}

/// `command_text_from_tool_payload` for a mapping tool input.
pub fn command_text(tool_name: Option<&str>, tool_input: &OMap) -> Option<String> {
    command_text_from_tool_payload(tool_name, tool_input)
}

/// `redacted_workspace_label` for a present workspace.
pub fn workspace_label(
    workspace: &str,
    home_dir: Option<&str>,
    env: &PathEnv,
) -> Result<String, AdapterError> {
    crate::hook_adapter_paths::workspace_label(workspace, home_dir, env)
}

/// `apply_patch_target_paths`.
pub fn apply_patch_paths(tool_input: &OMap) -> Vec<String> {
    crate::hook_adapter_envelope_text::apply_patch_target_paths(tool_input)
}
