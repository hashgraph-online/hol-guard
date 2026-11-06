//! User-facing incident copy for a Guard artifact decision.
//!
//! Every phrase a person reads when Guard pauses, flags or allows an
//! artifact is composed here from the decision and the artifact's evidence.
//! The text depends only on typed inputs, so each wording branch is covered by
//! recorded vectors from the original Python implementation.

use serde_json::{json, Value};

use guard_command::redacted_command_tokens::redact_text;

const HARNESS_LABELS: [(&str, &str); 12] = [
    ("codex", "Codex"),
    ("claude-code", "Claude Code"),
    ("copilot", "Copilot CLI"),
    ("cursor", "Cursor"),
    ("gemini", "Gemini"),
    ("opencode", "OpenCode"),
    ("pi", "Pi"),
    ("omp", "Oh My Pi"),
    ("zcode", "ZCode"),
    ("devin", "Devin"),
    ("grok", "Grok"),
    ("guard-cli", "Guard CLI"),
];
const ARTIFACT_LABELS: [(&str, &str); 13] = [
    ("mcp_server", "MCP server"),
    ("tool_call", "Tool call"),
    ("hook", "Hook"),
    ("agent", "Agent"),
    ("command", "Command"),
    ("package_request", "Package request"),
    ("prompt_request", "Prompt request"),
    ("file_read_request", "File read request"),
    ("skill", "Skill"),
    ("skill_file", "Skill file"),
    ("extension", "Extension"),
    ("instruction", "Instruction"),
    ("artifact", "Artifact"),
];
const DIRECT_INTERACTIONS: [&str; 3] = ["tool_call", "file_read_request", "prompt_request"];
const ACTIONS: [&str; 6] = [
    "allow",
    "warn",
    "review",
    "require-reapproval",
    "sandbox-required",
    "block",
];
const LAUNCH_TRUNCATE: usize = 140;

/// The decision-independent view of the artifact the copy reads.
#[derive(Default)]
struct IncidentArtifact {
    request_summary: Option<String>,
    prompt_summary: Option<String>,
    url: Option<String>,
    command: Option<String>,
    args: Vec<String>,
    watch_only_observation: bool,
    watch_only_authoritative_action: Option<String>,
    has_mcp_tool_identity: bool,
}

impl IncidentArtifact {
    fn from_value(value: &Value) -> Option<Self> {
        if value.is_null() {
            return None;
        }
        let metadata = value.get("metadata").unwrap_or(&Value::Null);
        let non_empty = |source: &Value, key: &str| {
            source
                .get(key)
                .and_then(Value::as_str)
                .filter(|text| !text.is_empty())
                .map(str::to_owned)
        };
        Some(Self {
            request_summary: non_empty(metadata, "request_summary"),
            prompt_summary: non_empty(metadata, "prompt_summary"),
            url: non_empty(value, "url"),
            command: non_empty(value, "command"),
            args: value
                .get("args")
                .and_then(Value::as_array)
                .map(|items| {
                    items
                        .iter()
                        .filter_map(Value::as_str)
                        .map(str::to_owned)
                        .collect()
                })
                .unwrap_or_default(),
            watch_only_observation: metadata.get("watch_only_observation")
                == Some(&Value::Bool(true)),
            watch_only_authoritative_action: metadata
                .get("watch_only_authoritative_action")
                .and_then(Value::as_str)
                .map(str::to_owned),
            has_mcp_tool_identity: metadata.get("mcp_tool_identity").is_some(),
        })
    }

    fn summary(&self) -> Option<&str> {
        self.request_summary
            .as_deref()
            .or(self.prompt_summary.as_deref())
    }

    fn command_parts(&self) -> Vec<&str> {
        let mut parts: Vec<&str> = self.command.iter().map(String::as_str).collect();
        parts.extend(self.args.iter().map(String::as_str));
        parts
    }
}

/// The caller-supplied identity of the artifact being described.
pub(crate) struct IncidentInput<'a> {
    pub harness: &'a str,
    pub artifact: &'a Value,
    pub artifact_id: &'a str,
    pub artifact_name: &'a str,
    pub artifact_type: Option<&'a str>,
    pub source_scope: Option<&'a str>,
    pub config_path: Option<&'a str>,
    pub changed_fields: &'a [String],
    pub policy_action: &'a str,
    pub launch_target: Option<&'a str>,
    pub risk_summary: Option<&'a str>,
}

/// Python `str.title()` for the unknown-harness fallback label.
fn title(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut in_word = false;
    for character in value.chars() {
        if in_word {
            out.extend(character.to_lowercase());
        } else {
            out.extend(character.to_uppercase());
        }
        in_word = character.is_lowercase() || character.is_uppercase();
    }
    out
}

fn lookup(table: &[(&'static str, &'static str)], key: &str) -> Option<&'static str> {
    table
        .iter()
        .find(|(name, _)| *name == key)
        .map(|(_, label)| *label)
}

fn truncate(value: &str) -> String {
    if value.chars().count() <= LAUNCH_TRUNCATE {
        return value.to_owned();
    }
    let kept: String = value.chars().take(LAUNCH_TRUNCATE - 1).collect();
    format!("{kept}\u{2026}")
}

fn redacted_command(parts: &[&str]) -> String {
    redact_text(&parts.join(" ")).text
}

fn short_config_path(config_path: Option<&str>) -> String {
    let Some(path) = config_path.filter(|path| !path.is_empty()) else {
        return "unknown config".to_owned();
    };
    let parts = path_parts(path);
    for marker in [".codex", ".claude", ".opencode"] {
        if let Some(index) = parts.iter().position(|part| part == marker) {
            return join_parts(&parts[index..]);
        }
    }
    if parts.len() >= 3 {
        return join_parts(&parts[parts.len() - 3..]);
    }
    if parts.len() >= 2 {
        return join_parts(&parts[parts.len() - 2..]);
    }
    match parts.last() {
        Some(last) if !is_anchor(last) => last.clone(),
        _ => path.to_owned(),
    }
}

fn separators(character: char) -> bool {
    character == '/' || (cfg!(windows) && character == '\\')
}

fn is_anchor(part: &str) -> bool {
    part.chars().all(separators) || (cfg!(windows) && part.ends_with(['\\', '/']))
}

/// `pathlib.PurePath(path).parts` for the host flavour.
fn path_parts(path: &str) -> Vec<String> {
    let mut parts = Vec::new();
    #[cfg(windows)]
    let (drive, rest) = {
        let bytes = path.as_bytes();
        if bytes.len() >= 2 && bytes[1] == b':' && bytes[0].is_ascii_alphabetic() {
            (Some(&path[..2]), &path[2..])
        } else {
            (None, path)
        }
    };
    #[cfg(not(windows))]
    let (drive, rest): (Option<&str>, &str) = (None, path);
    let root_len = rest
        .chars()
        .take_while(|character| separators(*character))
        .count();
    if drive.is_some() || root_len > 0 {
        let root = match root_len {
            0 => "",
            2 if !cfg!(windows) => "//",
            _ if cfg!(windows) => "\\",
            _ => "/",
        };
        parts.push(format!("{}{root}", drive.unwrap_or("")));
    }
    parts.extend(
        rest[root_len..]
            .split(separators)
            .filter(|part| !part.is_empty() && *part != ".")
            .map(str::to_owned),
    );
    parts
}

fn join_parts(parts: &[String]) -> String {
    let separator = if cfg!(windows) { "\\" } else { "/" };
    let mut out = String::new();
    for (index, part) in parts.iter().enumerate() {
        if index > 0 && !out.ends_with(separator) {
            out.push_str(separator);
        }
        out.push_str(part);
    }
    out
}

fn presentation_action<'a>(artifact: Option<&IncidentArtifact>, action: &'a str) -> &'a str {
    match artifact {
        Some(artifact) if artifact.watch_only_observation => {
            match artifact.watch_only_authoritative_action.as_deref() {
                Some("allow") => "allow",
                Some("warn") => "warn",
                _ => action,
            }
        }
        _ => action,
    }
}

fn trigger_verb(action: &str, changed_fields: &[String]) -> &'static str {
    match action {
        "allow" if changed_fields.is_empty() => "matched",
        "allow" => "reviewed",
        "warn" => "flagged",
        "block" => "blocked",
        _ => "paused",
    }
}

fn fallback_risk_headline(action: &str) -> &'static str {
    match action {
        "allow" => {
            "Policy allows this action; Guard found no high-confidence secret or network signal."
        }
        "warn" => "Policy allows this action with a warning.",
        "review" => "Policy requires review before this action can continue.",
        "require-reapproval" => "Policy requires fresh approval before this action can continue.",
        "sandbox-required" => "Policy requires this action to use an approved sandbox.",
        _ => "Policy blocks this action.",
    }
}

fn why_now(
    changed_fields: &[String],
    action: &str,
    harness_label: &str,
    artifact_type: Option<&str>,
) -> String {
    let normalized: Vec<String> = changed_fields
        .iter()
        .map(|field| field.trim().to_lowercase())
        .collect();
    let has = |name: &str| normalized.iter().any(|field| field == name);
    match action {
        "block" => {
            return "HOL Guard blocked this action because the authoritative policy does not permit it."
                .to_owned()
        }
        "sandbox-required" => {
            return "HOL Guard requires an approved sandbox before this action can continue.".to_owned()
        }
        "allow" | "warn" => return nonblocking_why_now(&normalized, action, harness_label, artifact_type),
        _ => {}
    }
    let workspace = harness_label.to_lowercase();
    if has("prompt_request") {
        "The prompt asks the agent to read a local .env file directly, so HOL Guard paused it until you approve that secret access.".to_owned()
    } else if has("file_read_request") {
        "The tool requested a protected local secret file, so HOL Guard paused the read until you approve it.".to_owned()
    } else if artifact_type == Some("tool_action_request") || has("tool_action_request") {
        "HOL Guard paused this native tool action because it can change the local machine before you confirm it.".to_owned()
    } else if artifact_type == Some("package_request") || has("package_request") {
        "HOL Guard paused this package change until you confirm the dependency action.".to_owned()
    } else if has("first_seen") {
        format!("It is new in this {workspace} workspace, so HOL Guard paused it for review.")
    } else if has("removed") {
        "It disappeared from the harness config, so HOL Guard paused the change until you confirm the removal.".to_owned()
    } else if has("command") || has("args") {
        "Its launch command changed, so HOL Guard is treating this as a new executable fingerprint."
            .to_owned()
    } else if has("url") || has("transport") {
        "Its connection target changed, so HOL Guard is treating this as a new remote endpoint."
            .to_owned()
    } else if has("publisher") {
        "Its publisher or source changed, so HOL Guard needs a fresh trust decision.".to_owned()
    } else {
        "HOL Guard found a meaningful config change and paused the launch for review.".to_owned()
    }
}

fn nonblocking_why_now(
    normalized: &[String],
    action: &str,
    harness_label: &str,
    artifact_type: Option<&str>,
) -> String {
    let outcome = if action == "allow" {
        "Policy allows the action to continue."
    } else {
        "Policy allows the action to continue with a warning."
    };
    let has = |name: &str| normalized.iter().any(|field| field == name);
    let workspace = harness_label.to_lowercase();
    if normalized.is_empty() && action == "allow" {
        "HOL Guard matched an existing allow rule for this exact version. The launch can continue."
            .to_owned()
    } else if has("removed") {
        format!(
            "HOL Guard recorded that the artifact was removed from the harness config. {outcome}"
        )
    } else if has("prompt_request") {
        format!("HOL Guard reviewed the prompt's request to read a local .env file. {outcome}")
    } else if has("file_read_request") {
        format!("HOL Guard reviewed the request to read a protected local secret file. {outcome}")
    } else if artifact_type == Some("tool_action_request") || has("tool_action_request") {
        format!("HOL Guard reviewed this native tool action because it can change the local machine. {outcome}")
    } else if artifact_type == Some("package_request") || has("package_request") {
        format!("HOL Guard reviewed this package dependency action. {outcome}")
    } else if has("first_seen") {
        format!("HOL Guard reviewed this new entry in the {workspace} workspace. {outcome}")
    } else if has("command") || has("args") {
        format!("HOL Guard reviewed the changed executable fingerprint. {outcome}")
    } else if has("url") || has("transport") {
        format!("HOL Guard reviewed the changed remote endpoint. {outcome}")
    } else if has("publisher") {
        format!("HOL Guard reviewed the changed publisher or source. {outcome}")
    } else {
        format!("HOL Guard reviewed a meaningful config change. {outcome}")
    }
}

fn launch_summary(
    artifact: Option<&IncidentArtifact>,
    launch_target: Option<&str>,
    artifact_type: Option<&str>,
    config_path: Option<&str>,
) -> String {
    if artifact_type.is_some_and(|kind| DIRECT_INTERACTIONS.contains(&kind)) {
        if let Some(summary) = artifact.and_then(IncidentArtifact::summary) {
            return summary.to_owned();
        }
        if artifact_type != Some("tool_call")
            || artifact.is_none_or(|artifact| artifact.has_mcp_tool_identity)
        {
            return "Guard reviewed this interaction directly. No shell launch command was recorded."
                .to_owned();
        }
    }
    if let Some(artifact) = artifact.filter(|artifact| {
        artifact_type == Some("tool_action_request") && artifact.command.is_some()
    }) {
        return format!(
            "Launches with `{}`.",
            redacted_command(&artifact.command_parts())
        );
    }
    if let Some(target) = launch_target.filter(|target| !target.is_empty()) {
        return if artifact_type == Some("tool_action_request") {
            format!("Launches with `{}`.", redact_text(target).text)
        } else {
            format!("Launches with `{}`.", truncate(target))
        };
    }
    if let Some(artifact) = artifact {
        if let Some(summary) = artifact.summary() {
            return summary.to_owned();
        }
        if let Some(url) = &artifact.url {
            return format!("Connects to `{url}`.");
        }
        if artifact.command.is_some() {
            return format!(
                "Launches with `{}`.",
                truncate(&redacted_command(&artifact.command_parts()))
            );
        }
    }
    match config_path.filter(|path| !path.is_empty()) {
        Some(path) => format!(
            "Guard reviewed the definition at {}. No separate shell launch command was recorded for this item.",
            short_config_path(Some(path))
        ),
        None => "Guard reviewed this item directly. No shell launch command was recorded.".to_owned(),
    }
}

/// The six incident strings, or `None` when the policy action is unknown.
pub(crate) fn build(input: &IncidentInput<'_>) -> Option<Value> {
    if !ACTIONS.contains(&input.policy_action) {
        return None;
    }
    let artifact = IncidentArtifact::from_value(input.artifact);
    let harness_label =
        lookup(&HARNESS_LABELS, input.harness).map_or_else(|| title(input.harness), str::to_owned);
    let artifact_label = lookup(
        &ARTIFACT_LABELS,
        input
            .artifact_type
            .filter(|kind| !kind.is_empty())
            .unwrap_or("artifact"),
    )
    .unwrap_or("Artifact");
    let scope = input
        .source_scope
        .filter(|scope| !scope.is_empty())
        .unwrap_or("project");
    let presentation = presentation_action(artifact.as_ref(), input.policy_action);
    let verb = trigger_verb(presentation, input.changed_fields);
    let name = if input.artifact_name.is_empty() {
        input.artifact_id
    } else {
        input.artifact_name
    };
    let (source_label, trigger_summary) = match input.artifact_type {
        Some("prompt_request") => (
            format!("{harness_label} session prompt"),
            format!("HOL Guard {verb} the {artifact_label} `{name}` from the active {harness_label} prompt."),
        ),
        Some("file_read_request") => (
            format!("{harness_label} runtime tool call"),
            format!("HOL Guard {verb} the {artifact_label} `{name}` from an active {harness_label} tool call."),
        ),
        Some("tool_action_request") => (
            format!("{harness_label} runtime tool call"),
            format!("HOL Guard {verb} the native tool action `{name}` from an active {harness_label} tool call."),
        ),
        Some("package_request") if input.harness == "guard-cli" => (
            "Local package command".to_owned(),
            format!("HOL Guard {verb} the package request `{name}` from a local package command."),
        ),
        Some("package_request") => (
            format!("{harness_label} command"),
            format!("HOL Guard {verb} the package request `{name}` from an active {harness_label} command."),
        ),
        _ => (
            format!("{scope} {harness_label} config"),
            format!(
                "HOL Guard {verb} the {artifact_label} `{name}` from `{}` for {harness_label}.",
                short_config_path(input.config_path)
            ),
        ),
    };
    let risk_headline = input
        .risk_summary
        .filter(|summary| !summary.is_empty())
        .map_or_else(
            || fallback_risk_headline(input.policy_action).to_owned(),
            str::to_owned,
        );
    Some(json!({
        "artifact_label": artifact_label,
        "source_label": source_label,
        "trigger_summary": trigger_summary,
        "why_now": why_now(input.changed_fields, presentation, &harness_label, input.artifact_type),
        "launch_summary": launch_summary(
            artifact.as_ref(),
            input.launch_target,
            input.artifact_type,
            input.config_path,
        ),
        "risk_headline": risk_headline,
    }))
}
