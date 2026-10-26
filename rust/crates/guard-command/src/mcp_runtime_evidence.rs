//! MCP tool-call runtime evidence: the `runtimeAction` record attached to
//! receipt scanner evidence and the human-readable command text. Faithful
//! port of the former Python `build_runtime_action_record` and
//! `extract_mcp_command_text`; Python now only transports DTOs.

use guard_contracts::McpRuntimeEnvelopeV1;
use regex::Regex;
use serde_json::{json, Value};
use std::collections::HashSet;
use std::sync::OnceLock;

use guard_contracts::{
    MCP_RUNTIME_EVIDENCE_COMMAND_ARGUMENT_KEYS as COMMAND_ARGUMENT_KEYS,
    MCP_RUNTIME_EVIDENCE_PATH_ARGUMENT_KEYS as PATH_ARGUMENT_KEYS,
    MCP_RUNTIME_EVIDENCE_PATH_TOKENS as ARGUMENT_PATH_TOKENS,
};

/// One ordered argument entry: stringified key, string value (else `None`).
pub type ArgumentEntry = (String, Option<String>);

/// Python `str.isspace` (Unicode White_Space plus the C0 separators).
fn is_py_space(c: char) -> bool {
    c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c)
}

fn py_strip(value: &str) -> &str {
    value.trim_matches(is_py_space)
}

fn package_manager_pattern() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| {
        Regex::new(r"(?i)\b(npm|pnpm|yarn|bun|pip|uv|cargo|gem|brew)\b").expect("static pattern")
    })
}

fn sensitive_class_pattern() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| {
        Regex::new(r"(?i)(secret|token|credential|password|api[_-]?key|pii|phi|payment)")
            .expect("static pattern")
    })
}

fn argument_value<'a>(entries: &'a [ArgumentEntry], key: &str) -> Option<&'a str> {
    // Mapping semantics: keys are unique, so at most one entry matches.
    entries
        .iter()
        .find(|(entry_key, _)| entry_key == key)
        .and_then(|(_, value)| value.as_deref())
}

/// `extract_mcp_command_text`: the command string, else `"<tool> <path>"`.
pub fn extract_command_text(
    artifact_name: &str,
    arguments: Option<&[ArgumentEntry]>,
) -> Option<String> {
    let entries = arguments?;
    for key in COMMAND_ARGUMENT_KEYS.iter().copied() {
        if let Some(value) = argument_value(entries, key) {
            let stripped = py_strip(value);
            if !stripped.is_empty() {
                return Some(stripped.to_owned());
            }
        }
    }
    for key in PATH_ARGUMENT_KEYS.iter().copied() {
        if let Some(value) = argument_value(entries, key) {
            let stripped = py_strip(value);
            if !stripped.is_empty() {
                return Some(format!("{artifact_name} {stripped}"));
            }
        }
    }
    None
}

fn argument_paths(arguments: Option<&[ArgumentEntry]>) -> Vec<&str> {
    arguments
        .unwrap_or_default()
        .iter()
        .filter_map(|(key, value)| {
            let normalized = key.to_lowercase();
            let value = value.as_deref()?;
            ARGUMENT_PATH_TOKENS
                .iter()
                .any(|token| normalized.contains(token))
                .then_some(value)
        })
        .collect()
}

fn redact_path(path: &str) -> String {
    let normalized = path.replace('\\', "/");
    match normalized.split('/').rfind(|segment| !segment.is_empty()) {
        Some(last) => format!("[redacted]/{last}"),
        None => "[redacted-path]".to_owned(),
    }
}

fn unique_strings<I, S>(values: I) -> Vec<String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut seen = HashSet::new();
    let mut ordered = Vec::new();
    for value in values {
        let normalized = py_strip(value.as_ref());
        if normalized.is_empty() || !seen.insert(normalized.to_owned()) {
            continue;
        }
        ordered.push(normalized.to_owned());
    }
    ordered
}

/// `build_runtime_action_record`: `None` when every field is empty.
pub fn runtime_action_record(
    tool_description: Option<&str>,
    arguments: Option<&[ArgumentEntry]>,
    risk_categories: &[String],
    envelope: Option<&McpRuntimeEnvelopeV1>,
) -> Option<Value> {
    let mut files_touched: Vec<String> = argument_paths(arguments)
        .into_iter()
        .map(redact_path)
        .collect();
    let mut domains: Vec<String> = Vec::new();
    let mut subprocesses: Vec<String> = Vec::new();
    let mut package_managers: Vec<String> = Vec::new();
    if let Some(envelope) = envelope {
        files_touched.extend(envelope.target_paths.iter().map(|path| redact_path(path)));
        domains.extend(envelope.network_hosts.iter().cloned());
        if let Some(manager) = envelope.package_manager.as_ref().filter(|m| !m.is_empty()) {
            package_managers.push(manager.clone());
        }
        if let Some(command) = envelope.command.as_ref().filter(|c| !c.is_empty()) {
            // Python `command.split()[0]` raised on whitespace-only commands;
            // a command with no program token contributes no subprocess.
            if let Some(program) = command.split(is_py_space).find(|part| !part.is_empty()) {
                subprocesses.push(program.to_owned());
            }
        }
    }
    let claimed: Vec<&str> = match tool_description {
        Some(description) if !py_strip(description).is_empty() => vec!["tool_description"],
        _ => Vec::new(),
    };
    let observed: Vec<&String> = risk_categories.iter().collect();
    let sensitive: Vec<&str> = risk_categories
        .iter()
        .map(String::as_str)
        .chain(claimed.iter().copied())
        .chain(risk_categories.iter().map(String::as_str))
        .filter(|category| sensitive_class_pattern().is_match(category))
        .collect();
    for subprocess in &subprocesses {
        if let Some(found) = package_manager_pattern().captures(subprocess) {
            package_managers.push(found[1].to_lowercase());
        }
    }
    let claimed_values: Vec<&str> = claimed;
    let payload = json!({
        "claimedCapabilities": claimed_values,
        "domainsContacted": unique_strings(&domains),
        "filesTouched": unique_strings(&files_touched),
        "observedCapabilities": observed,
        "packageManagersInvoked": unique_strings(&package_managers),
        "sensitiveDataClasses": unique_strings(sensitive),
        "subprocessesSpawned": unique_strings(&subprocesses),
    });
    let any_value = payload.as_object().is_some_and(|map| {
        map.values()
            .any(|v| v.as_array().is_some_and(|a| !a.is_empty()))
    });
    any_value.then_some(payload)
}
