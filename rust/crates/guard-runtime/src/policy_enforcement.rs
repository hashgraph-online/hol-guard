#![forbid(unsafe_code)]

//! Apply the authenticated effective policy to native hook results.
//!
//! The hook classifiers establish an intrinsic minimum action from the raw
//! request.  This module only joins that result with the already-installed
//! policy snapshot.  It never replaces a stronger native result with a
//! weaker policy value and it never reads configuration or request content
//! outside the native edge.
//!
//! `warn` is an allow-with-warning action, not a deny. In `observe` mode a
//! policy-only floor is surfaced as a warning (so it cannot deny execution),
//! while an intrinsic native floor is preserved. Intrinsic `block` remains
//! hard in every mode.

use guard_contracts::{
    GuardHookPayloadKindV2, HookReviewResponseV1, NativeHookRequestV1, PreToolActionTypeV1,
    PreToolResultV1,
};
use guard_policy_snapshot::{EffectiveNativePolicyV3, PolicySnapshotV3};
use guard_secure_fs::sensitive_path_family;
use serde_json::{Map, Value};
use std::collections::BTreeMap;
use std::path::Path;

const VALID_ACTIONS: &[&str] = &[
    "allow",
    "warn",
    "review",
    "require-reapproval",
    "sandbox-required",
    "block",
];

const VALID_RISK_KEYS: &[&str] = &[
    "local_secret_read",
    "credential_exfiltration",
    "data_flow_exfiltration",
    "destructive_shell",
    "encoded_execution",
    "network_egress",
    "prompt_injection",
    "mcp_dangerous_tool",
    "malicious_skill",
    "package_script",
    "persistence",
    "guard_bypass",
    "cloud_advisory",
    "encoded_exfiltration",
    "execution",
    "supply_chain",
    "policy_bypass",
];

const MAX_SELECTOR_VALUE_BYTES: usize = 4 * 1024;
const MAX_FACT_DEPTH: usize = 32;
const MAX_FACT_NODES: usize = 2_048;

const PUBLISHER_KEYS: &[&str] = &[
    "publisher",
    "publisher_id",
    "publisherId",
    "publisher_name",
    "publisherName",
];
const ARTIFACT_KEYS: &[&str] = &[
    "artifact",
    "artifact_id",
    "artifactId",
    "package",
    "package_name",
    "packageName",
    "plugin_id",
    "pluginId",
    "extension_id",
    "extensionId",
    "skill_id",
    "skillId",
];
const PATH_KEYS: &[&str] = &[
    "path",
    "file",
    "file_path",
    "filePath",
    "target_file",
    "targetFile",
    "target_directory",
    "targetDirectory",
];
const CHANGED_BOOL_KEYS: &[&str] = &[
    "changed",
    "hash_changed",
    "hashChanged",
    "changed_hash",
    "changedHash",
    "source_changed",
    "sourceChanged",
    "source_hash_changed",
    "sourceHashChanged",
    "content_changed",
    "contentChanged",
];
const CHANGED_CAPABILITY_KEYS: &[&str] = &["changed_capabilities", "changedCapabilities"];

#[derive(Debug, Default)]
struct PolicyFacts {
    publisher: Option<String>,
    artifact: Option<String>,
    changed_hash: bool,
    sensitive_target: bool,
    publisher_relevant: bool,
}

/// The same total order as the Python action lattice and the v3 snapshot
/// validator.  Keep this local to the native data plane so policy composition
/// cannot depend on a Python semantic helper.
fn action_rank(action: &str) -> Option<u8> {
    Some(match action {
        "allow" => 0,
        "warn" => 1,
        "review" => 2,
        "require-reapproval" => 3,
        "sandbox-required" => 4,
        "block" => 5,
        _ => return None,
    })
}

fn join_action(left: &str, right: &str) -> Result<String, String> {
    let left_rank = action_rank(left).ok_or_else(|| "native_policy_action_invalid".to_owned())?;
    let right_rank = action_rank(right).ok_or_else(|| "native_policy_action_invalid".to_owned())?;
    Ok(if left_rank >= right_rank {
        left.to_owned()
    } else {
        right.to_owned()
    })
}

fn canonical_harness(value: &str) -> Option<&str> {
    let normalized = value.trim().to_ascii_lowercase().replace('_', "-");
    match normalized.as_str() {
        "claude" => Some("claude-code"),
        "cline-cli" | "cline-vscode" => Some("cline"),
        "kimi-code" | "kimi-cli" => Some("kimi"),
        "grok-build" | "grok-build-cli" | "xai-grok" => Some("grok"),
        "pi-agent" | "pi-coding-agent" => Some("pi"),
        "oh-my-pi" => Some("omp"),
        "zai" | "z-code" | "zai-zcode" => Some("zcode"),
        _ => None,
    }
}

fn normalized_harness(value: &str) -> String {
    let normalized = value.trim().to_ascii_lowercase().replace('_', "-");
    canonical_harness(&normalized)
        .unwrap_or(normalized.as_str())
        .to_owned()
}

fn policy_map_action(
    map: &std::collections::BTreeMap<String, String>,
    key: &str,
) -> Result<Option<String>, String> {
    let Some(value) = map.get(key) else {
        return Ok(None);
    };
    if !VALID_ACTIONS.contains(&value.as_str()) {
        return Err("native_policy_action_invalid".to_owned());
    }
    Ok(Some(value.clone()))
}

fn valid_selector_key(value: &str, harness: bool) -> bool {
    if value.trim().is_empty() || value.len() > MAX_SELECTOR_VALUE_BYTES {
        return false;
    }
    if harness {
        value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
    } else {
        true
    }
}

fn validate_action_map(
    map: &BTreeMap<String, String>,
    risk_keys: bool,
    harness_keys: bool,
) -> Result<(), String> {
    for (key, action) in map {
        if !valid_selector_key(key, harness_keys) || !VALID_ACTIONS.contains(&action.as_str()) {
            return Err("native_policy_invalid".to_owned());
        }
        if risk_keys && !VALID_RISK_KEYS.contains(&key.as_str()) {
            return Err("native_policy_unknown_risk_selector".to_owned());
        }
    }
    Ok(())
}

fn validate_effective_policy(policy: &EffectiveNativePolicyV3) -> Result<(), String> {
    for action in [
        &policy.default_action,
        &policy.unknown_publisher_action,
        &policy.changed_hash_action,
        &policy.new_network_domain_action,
        &policy.subprocess_action,
    ] {
        if !VALID_ACTIONS.contains(&action.as_str()) {
            return Err("native_policy_action_invalid".to_owned());
        }
    }
    if !matches!(
        policy.protection_posture.as_str(),
        "protected" | "extra_careful" | "watch"
    ) || !matches!(
        policy.security_level.as_str(),
        "relaxed" | "gentle" | "balanced" | "strict" | "paranoid" | "custom"
    ) || !matches!(
        policy.sandbox_analysis.as_str(),
        "off" | "suspicious" | "strict"
    ) || !matches!(
        policy.receipt_redaction_level.as_str(),
        "full" | "partial" | "none"
    ) {
        return Err("native_policy_invalid".to_owned());
    }
    validate_action_map(&policy.risk_actions, true, false)?;
    validate_action_map(&policy.harness_actions, false, true)?;
    validate_action_map(&policy.publisher_actions, false, false)?;
    validate_action_map(&policy.artifact_actions, false, false)?;
    for (harness, actions) in &policy.harness_risk_actions {
        if !valid_selector_key(harness, true) {
            return Err("native_policy_invalid".to_owned());
        }
        validate_action_map(actions, true, false)?;
    }
    Ok(())
}

fn canonical_harness_action(
    map: &std::collections::BTreeMap<String, String>,
    harness: &str,
) -> Result<Option<String>, String> {
    let mut selected: Option<(&str, &str)> = None;
    for (configured, action) in map {
        if !VALID_ACTIONS.contains(&action.as_str()) {
            return Err("native_policy_action_invalid".to_owned());
        }
        let normalized = normalized_harness(configured);
        if normalized != harness {
            continue;
        }
        if let Some((_, previous_action)) = selected {
            if previous_action != action {
                return Err("native_policy_harness_selector_conflict".to_owned());
            }
        } else {
            selected = Some((configured.as_str(), action.as_str()));
        }
    }
    Ok(selected.map(|(_, action)| action.to_owned()))
}

fn canonical_harness_risk_actions<'a>(
    map: &'a BTreeMap<String, BTreeMap<String, String>>,
    harness: &str,
) -> Result<Option<&'a BTreeMap<String, String>>, String> {
    let mut selected: Option<&'a BTreeMap<String, String>> = None;
    for (configured, actions) in map {
        if normalized_harness(configured) != harness {
            continue;
        }
        if let Some(previous) = selected {
            if previous != actions {
                return Err("native_policy_harness_selector_conflict".to_owned());
            }
        } else {
            selected = Some(actions);
        }
    }
    Ok(selected)
}

fn collect_fact_maps<'a>(
    value: &'a Value,
    depth: usize,
    nodes: &mut usize,
    output: &mut Vec<&'a Map<String, Value>>,
) -> Result<(), String> {
    if depth > MAX_FACT_DEPTH {
        return Err("native_policy_request_bounds_exceeded".to_owned());
    }
    *nodes = nodes.saturating_add(1);
    if *nodes > MAX_FACT_NODES {
        return Err("native_policy_request_bounds_exceeded".to_owned());
    }
    match value {
        Value::Object(record) => {
            output.push(record);
            for child in record.values() {
                collect_fact_maps(child, depth.saturating_add(1), nodes, output)?;
            }
        }
        Value::Array(items) => {
            for child in items {
                collect_fact_maps(child, depth.saturating_add(1), nodes, output)?;
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
    Ok(())
}

fn bounded_selector_value(value: &str) -> Result<String, String> {
    let value = value.trim();
    if value.is_empty()
        || value.len() > MAX_SELECTOR_VALUE_BYTES
        || value.chars().count() > MAX_SELECTOR_VALUE_BYTES
    {
        return Err("native_policy_selector_invalid".to_owned());
    }
    Ok(value.to_owned())
}

fn optional_identity(
    maps: &[&Map<String, Value>],
    keys: &[&str],
) -> Result<Option<String>, String> {
    let mut selected: Option<String> = None;
    for record in maps {
        for key in keys {
            let Some(value) = record.get(*key) else {
                continue;
            };
            // Some harnesses carry a full artifact/publisher object. It is not
            // an authenticated selector, so leave it unknown and apply the
            // conservative unknown-publisher floor instead of guessing.
            let Some(value) = value.as_str() else {
                if key.ends_with("_id") || key.ends_with("Id") {
                    return Err("native_policy_selector_invalid".to_owned());
                }
                continue;
            };
            let value = bounded_selector_value(value)?;
            if selected
                .as_deref()
                .is_some_and(|previous| previous != value)
            {
                return Err("native_policy_selector_conflict".to_owned());
            }
            selected = Some(value);
        }
    }
    Ok(selected)
}

fn path_values_sensitive(maps: &[&Map<String, Value>]) -> Result<bool, String> {
    let mut sensitive = false;
    for record in maps {
        for key in PATH_KEYS {
            let Some(value) = record.get(*key) else {
                continue;
            };
            let values: Vec<&str> = match value {
                Value::String(value) => vec![value.as_str()],
                Value::Array(values) => values
                    .iter()
                    .map(|item| {
                        item.as_str()
                            .ok_or_else(|| "native_policy_path_invalid".to_owned())
                    })
                    .collect::<Result<_, _>>()?,
                // An object under `file` or `path` is metadata, not a path
                // selector. The native source reader still validates it.
                Value::Object(_) | Value::Null | Value::Bool(_) | Value::Number(_) => continue,
            };
            sensitive |= values
                .into_iter()
                .any(|value| sensitive_path_family(Path::new(value)).is_some());
        }
    }
    Ok(sensitive)
}

fn sensitive_key(key: &str) -> bool {
    let normalized = key.to_ascii_lowercase().replace(['_', '-'], "");
    [
        "password",
        "passwd",
        "secret",
        "token",
        "credential",
        "privatekey",
        "apikey",
        "accesskey",
        "authorization",
    ]
    .iter()
    .any(|marker| normalized.contains(marker))
}

fn payload_sensitive_target(maps: &[&Map<String, Value>]) -> Result<bool, String> {
    let mut sensitive = path_values_sensitive(maps)?;
    for record in maps {
        for (key, value) in *record {
            if key == "sensitive_target" {
                let value = value
                    .as_bool()
                    .ok_or_else(|| "native_policy_sensitive_target_invalid".to_owned())?;
                sensitive |= value;
            } else if sensitive_key(key) {
                sensitive = true;
            }
        }
    }
    Ok(sensitive)
}

fn optional_changed_bool(maps: &[&Map<String, Value>]) -> Result<bool, String> {
    let mut selected: Option<bool> = None;
    let mut select = |value: bool| -> Result<(), String> {
        if selected.is_some_and(|previous| previous != value) {
            return Err("native_policy_changed_hash_conflict".to_owned());
        }
        selected = Some(value);
        Ok(())
    };
    for record in maps {
        for key in CHANGED_BOOL_KEYS {
            let Some(value) = record.get(*key) else {
                continue;
            };
            let value = value
                .as_bool()
                .ok_or_else(|| "native_policy_changed_hash_invalid".to_owned())?;
            select(value)?;
        }
        for key in CHANGED_CAPABILITY_KEYS {
            let Some(value) = record.get(*key) else {
                continue;
            };
            match value {
                Value::String(value) => {
                    let changed = value.trim().eq_ignore_ascii_case("changed_hash")
                        || value.trim().eq_ignore_ascii_case("hash_changed")
                        || value.trim().eq_ignore_ascii_case("source_changed");
                    if changed {
                        select(true)?;
                    }
                }
                Value::Array(values) => {
                    for item in values {
                        let item = item
                            .as_str()
                            .ok_or_else(|| "native_policy_changed_hash_invalid".to_owned())?;
                        if item.eq_ignore_ascii_case("changed_hash")
                            || item.eq_ignore_ascii_case("hash_changed")
                            || item.eq_ignore_ascii_case("source_changed")
                        {
                            select(true)?;
                        }
                    }
                }
                _ => return Err("native_policy_changed_hash_invalid".to_owned()),
            }
        }
    }
    Ok(selected.unwrap_or(false))
}

fn optional_hash(maps: &[&Map<String, Value>], keys: &[&str]) -> Result<Option<String>, String> {
    let mut selected: Option<String> = None;
    for record in maps {
        for key in keys {
            let Some(value) = record.get(*key) else {
                continue;
            };
            let Some(value) = value.as_str() else {
                return Err("native_policy_changed_hash_invalid".to_owned());
            };
            let value = bounded_selector_value(value)?;
            if selected
                .as_deref()
                .is_some_and(|previous| previous != value)
            {
                return Err("native_policy_changed_hash_conflict".to_owned());
            }
            selected = Some(value);
        }
    }
    Ok(selected)
}

fn payload_changed_hash(maps: &[&Map<String, Value>]) -> Result<bool, String> {
    let explicit = optional_changed_bool(maps)?;
    let previous = optional_hash(
        maps,
        &["previous_hash", "previousHash", "prior_hash", "priorHash"],
    )?;
    let current = optional_hash(
        maps,
        &[
            "current_hash",
            "currentHash",
            "actual_hash",
            "actualHash",
            "source_hash",
            "sourceHash",
            "output_sha256",
            "outputSha256",
        ],
    )?;
    Ok(explicit || previous.is_some() && current.is_some() && previous != current)
}

fn payload_facts(
    payload: &Value,
    action_type: PreToolActionTypeV1,
    reason_code: &str,
) -> Result<PolicyFacts, String> {
    let mut maps = Vec::new();
    let mut nodes = 0usize;
    collect_fact_maps(payload, 0, &mut nodes, &mut maps)?;
    let publisher = optional_identity(&maps, PUBLISHER_KEYS)?;
    let artifact = optional_identity(&maps, ARTIFACT_KEYS)?;
    let sensitive_target = payload_sensitive_target(&maps)?
        || reason_code.contains("secret")
        || reason_code.contains("credential")
        || reason_code.contains("exfiltration");
    let publisher_relevant = publisher.is_some()
        || artifact.is_some()
        || matches!(
            action_type,
            PreToolActionTypeV1::Package | PreToolActionTypeV1::McpTool
        );
    Ok(PolicyFacts {
        publisher,
        artifact,
        changed_hash: payload_changed_hash(&maps)?,
        sensitive_target,
        publisher_relevant,
    })
}

fn preferred_tool_name(maps: &[&Map<String, Value>]) -> Result<Option<String>, String> {
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

fn tool_matches(tool: &str, terms: &[&str]) -> bool {
    let normalized: String = tool
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect();
    terms.iter().any(|term| {
        let term: String = term
            .chars()
            .filter(|character| character.is_ascii_alphanumeric())
            .flat_map(char::to_lowercase)
            .collect();
        normalized.contains(&term)
    })
}

fn classify_tool_name(tool: &str) -> PreToolActionTypeV1 {
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

fn risk_classes(
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

fn policy_floor(
    policy: &EffectiveNativePolicyV3,
    harness: &str,
    action_type: PreToolActionTypeV1,
    facts: &PolicyFacts,
    reason_code: &str,
) -> Result<String, String> {
    validate_effective_policy(policy)?;
    let mut floor = policy.default_action.clone();
    if let Some(action) = canonical_harness_action(&policy.harness_actions, harness)? {
        floor = join_action(&floor, &action)?;
    }
    if matches!(
        action_type,
        PreToolActionTypeV1::Command | PreToolActionTypeV1::ProcessService
    ) {
        floor = join_action(&floor, &policy.subprocess_action)?;
    }
    if matches!(
        action_type,
        PreToolActionTypeV1::Network | PreToolActionTypeV1::Browser
    ) {
        floor = join_action(&floor, &policy.new_network_domain_action)?;
    }
    if action_type == PreToolActionTypeV1::Unknown {
        // An unknown PostToolUse operation has no safe automatic allow
        // proof, even when the configured default is permissive.
        floor = join_action(&floor, "review")?;
    }
    if facts.changed_hash {
        floor = join_action(&floor, &policy.changed_hash_action)?;
    }
    if facts.publisher_relevant && facts.publisher.is_none() {
        floor = join_action(&floor, &policy.unknown_publisher_action)?;
    }
    if let Some(artifact) = facts.artifact.as_deref() {
        if let Some(action) = policy_map_action(&policy.artifact_actions, artifact)? {
            floor = join_action(&floor, &action)?;
        }
    }
    if let Some(publisher) = facts.publisher.as_deref() {
        if let Some(action) = policy_map_action(&policy.publisher_actions, publisher)? {
            floor = join_action(&floor, &action)?;
        }
    }
    let harness_risks = canonical_harness_risk_actions(&policy.harness_risk_actions, harness)?;
    for risk in risk_classes(action_type, facts.sensitive_target, reason_code) {
        if let Some(action) = policy_map_action(&policy.risk_actions, risk)? {
            floor = join_action(&floor, &action)?;
        }
        if let Some(harness_map) = harness_risks {
            if let Some(action) = policy_map_action(harness_map, risk)? {
                floor = join_action(&floor, &action)?;
            }
        }
    }
    Ok(floor)
}

fn policy_override_reason(action: &str) -> (&'static str, &'static str) {
    match action {
        "block" => (
            "native_policy_block",
            "HOL Guard blocked this hook action under the installed native policy.",
        ),
        "sandbox-required" => (
            "native_policy_sandbox_required",
            "HOL Guard requires sandbox enforcement under the installed native policy.",
        ),
        "require-reapproval" => (
            "native_policy_reapproval_required",
            "HOL Guard requires fresh approval under the installed native policy.",
        ),
        "review" => (
            "native_policy_review_required",
            "HOL Guard requires review under the installed native policy.",
        ),
        _ => (
            "native_policy_warning",
            "HOL Guard raised this action under the installed native policy.",
        ),
    }
}

/// Apply the authenticated policy to a generic native PreTool result.
pub(crate) fn apply_pre_tool_policy(
    snapshot: &PolicySnapshotV3,
    payload: &Value,
    result: PreToolResultV1,
) -> Result<PreToolResultV1, String> {
    if !matches!(snapshot.mode.as_str(), "enforce" | "observe") {
        return Err("native_policy_mode_invalid".to_owned());
    }
    let harness = normalized_harness(&result.action.harness);
    let mut facts = payload_facts(payload, result.action.action_type, &result.reason_code)?;
    facts.sensitive_target |= result.action.sensitive_target;
    let policy_floor = policy_floor(
        &snapshot.effective_policy,
        &harness,
        result.action.action_type,
        &facts,
        &result.reason_code,
    )?;
    let effective = join_action(&result.minimum_action, &policy_floor)?;
    let policy_raised = action_rank(&effective) > action_rank(&result.minimum_action);
    let mut output = result;

    if snapshot.mode == "observe" {
        // Observe suppresses only an escalation introduced by the installed
        // policy. Every intrinsic review, reapproval, sandbox, block, and
        // malformed/unknown result remains authoritative. A native block
        // paired with an inconsistent allow decision is repaired fail-closed.
        let intrinsic_rank = action_rank(&output.minimum_action)
            .ok_or_else(|| "native_policy_action_invalid".to_owned())?;
        let policy_only_warning = policy_raised
            && intrinsic_rank <= action_rank("warn").unwrap_or(1)
            && output.decision == "allow";
        if policy_only_warning {
            output.reason_code = "native_policy_warning".to_owned();
            output.reason =
                "HOL Guard observed a stricter installed native policy floor.".to_owned();
            output.policy_action = "warn".to_owned();
            output.minimum_action = "warn".to_owned();
            output.decision = "allow".to_owned();
            output.explicitly_benign = false;
        } else {
            output.policy_action = effective;
            if intrinsic_rank >= action_rank("block").unwrap_or(5) && output.decision == "allow" {
                output.decision = "deny".to_owned();
                output.explicitly_benign = false;
            }
        }
        return Ok(output);
    }

    if policy_raised {
        let (reason_code, reason) = policy_override_reason(&effective);
        output.reason_code = reason_code.to_owned();
        output.reason = reason.to_owned();
    }
    output.policy_action = effective.clone();
    output.minimum_action = effective.clone();
    output.decision = if matches!(effective.as_str(), "allow" | "warn") {
        "allow".to_owned()
    } else {
        "deny".to_owned()
    };
    output.explicitly_benign = effective == "allow";
    Ok(output)
}

fn post_action_type(
    request: &NativeHookRequestV1,
    payload_kind: GuardHookPayloadKindV2,
) -> Result<PreToolActionTypeV1, String> {
    if payload_kind == GuardHookPayloadKindV2::SourceFileRef {
        return Ok(PreToolActionTypeV1::FileRead);
    }
    let mut maps = Vec::new();
    let mut nodes = 0usize;
    collect_fact_maps(&request.payload, 0, &mut nodes, &mut maps)?;
    if let Some(tool) = preferred_tool_name(&maps)? {
        return Ok(classify_tool_name(&tool));
    }
    for record in maps {
        if record.keys().any(|key| {
            matches!(
                key.as_str(),
                "command" | "cmd" | "shell_command" | "shellCommand"
            )
        }) {
            return Ok(PreToolActionTypeV1::Command);
        }
        if record
            .keys()
            .any(|key| matches!(key.as_str(), "package" | "package_name" | "packageName"))
        {
            return Ok(PreToolActionTypeV1::Package);
        }
        if record.keys().any(|key| PATH_KEYS.contains(&key.as_str())) {
            return Ok(PreToolActionTypeV1::FileRead);
        }
        if record
            .keys()
            .any(|key| matches!(key.as_str(), "url" | "uri" | "href" | "endpoint"))
        {
            return Ok(PreToolActionTypeV1::Network);
        }
    }
    Ok(PreToolActionTypeV1::Unknown)
}

/// Apply the authenticated policy to a Rust-owned PostTool result. The
/// source/content decision is intrinsic and therefore remains strongest even
/// when the configured policy says `allow`.
pub(crate) fn apply_post_tool_policy(
    snapshot: &PolicySnapshotV3,
    request: &NativeHookRequestV1,
    payload_kind: GuardHookPayloadKindV2,
    mut response: HookReviewResponseV1,
) -> Result<HookReviewResponseV1, String> {
    if !matches!(snapshot.mode.as_str(), "enforce" | "observe") {
        return Err("native_policy_mode_invalid".to_owned());
    }
    let action_type = post_action_type(request, payload_kind)?;
    let intrinsic = response
        .observed_policy_action
        .as_deref()
        .or(response.policy_action.as_deref())
        .unwrap_or(if response.decision == "deny" {
            "block"
        } else if response.model_output_action == "replace_with_reviewed_excerpt" {
            "review"
        } else {
            "allow"
        })
        .to_owned();
    if action_rank(&intrinsic).is_none() {
        return Err("native_post_tool_policy_invalid_result".to_owned());
    }
    let facts = payload_facts(&request.payload, action_type, &response.reason_code)?;
    let floor = policy_floor(
        &snapshot.effective_policy,
        &normalized_harness(&request.harness),
        action_type,
        &facts,
        &response.reason_code,
    )?;
    let effective = join_action(&intrinsic, &floor)?;
    response.policy_action = Some(effective.clone());
    if snapshot.mode == "observe" && intrinsic != "block" {
        return Ok(response);
    }
    if snapshot.mode == "observe" && intrinsic == "block" && response.decision == "allow" {
        // Observe suppresses policy-only floors, but it cannot turn an
        // intrinsic native source/content block into an allow.
        let mut denied = HookReviewResponseV1::deny(
            response.reason_code.clone(),
            "HOL Guard retained an intrinsic native block in observe mode.",
        );
        denied.policy_action = Some("block".to_owned());
        denied.observed_policy_action = Some("block".to_owned());
        denied.observe_mode = true;
        return Ok(denied);
    }
    if effective == "allow" {
        return Ok(response);
    }
    if effective == "warn" && response.decision == "allow" {
        if intrinsic != "warn" {
            response.reason_code = "native_policy_warning".to_owned();
            response.reason = Some(
                "HOL Guard raised a non-blocking warning under the installed native policy."
                    .to_owned(),
            );
            response.notice = "warning".to_owned();
        }
        return Ok(response);
    }
    if intrinsic == "review"
        && effective == "review"
        && response.decision == "allow"
        && response.model_output_action == "replace_with_reviewed_excerpt"
    {
        // A reviewed excerpt already satisfies the intrinsic review floor.
        return Ok(response);
    }
    if intrinsic == "block" && response.decision == "deny" {
        return Ok(response);
    }
    let (reason_code, reason) = policy_override_reason(&effective);
    let mut denied = HookReviewResponseV1::deny(reason_code, reason);
    denied.policy_action = Some(effective);
    Ok(denied)
}

#[cfg(test)]
mod tests {
    use super::*;
    use guard_contracts::{
        PreToolActionV1, PreToolOperationV1, NATIVE_PROTOCOL_VERSION, PRE_TOOL_ACTION_V1_SCHEMA,
    };
    use guard_policy_snapshot::{
        EffectiveNativePolicyV3, ScopeContractV3, SnapshotIntegrityV3,
        POLICY_SNAPSHOT_INTEGRITY_ALGORITHM, POLICY_SNAPSHOT_SCHEMA,
    };
    use serde_json::json;
    use std::collections::BTreeMap;

    fn policy(default_action: &str) -> EffectiveNativePolicyV3 {
        EffectiveNativePolicyV3 {
            protection_posture: "protected".into(),
            security_level: "balanced".into(),
            default_action: default_action.into(),
            unknown_publisher_action: "review".into(),
            changed_hash_action: "require-reapproval".into(),
            new_network_domain_action: "allow".into(),
            subprocess_action: "allow".into(),
            risk_actions: BTreeMap::new(),
            harness_risk_actions: BTreeMap::new(),
            harness_actions: BTreeMap::new(),
            publisher_actions: BTreeMap::new(),
            artifact_actions: BTreeMap::new(),
            sandbox_analysis: "off".into(),
            receipt_redaction_level: "full".into(),
        }
    }

    fn snapshot(policy: EffectiveNativePolicyV3) -> PolicySnapshotV3 {
        PolicySnapshotV3 {
            schema: POLICY_SNAPSHOT_SCHEMA.into(),
            version: 3,
            generation: 1,
            policy_digest: "a".repeat(64),
            config_digest: "b".repeat(64),
            rule_digest: "c".repeat(64),
            runtime_identity: "d".repeat(64),
            protocol_version: 1,
            mode: "enforce".into(),
            scope_contract: ScopeContractV3 {
                schema: "guard-native-scope.v1".into(),
                kind: "guard-home".into(),
                scope_digest: "e".repeat(64),
                workspace_binding: "request-source".into(),
            },
            effective_policy: policy,
            issued_at_ms: 1,
            expires_at_ms: 2,
            integrity: SnapshotIntegrityV3 {
                algorithm: POLICY_SNAPSHOT_INTEGRITY_ALGORITHM.into(),
                key_id: "f".repeat(64),
                mac: "0".repeat(64),
            },
        }
    }

    fn generic_result(minimum_action: &str) -> PreToolResultV1 {
        PreToolResultV1 {
            schema: "guard-pre-tool-result.v1".into(),
            version: 1,
            authority: "rust".into(),
            action: PreToolActionV1 {
                schema: PRE_TOOL_ACTION_V1_SCHEMA.into(),
                version: 1,
                harness: "claude-code".into(),
                event: "PreToolUse".into(),
                action_type: PreToolActionTypeV1::Command,
                operation: PreToolOperationV1::Execute,
                bounded: true,
                sensitive_target: false,
            },
            decision: if matches!(minimum_action, "allow" | "warn") {
                "allow"
            } else {
                "deny"
            }
            .into(),
            policy_action: minimum_action.into(),
            minimum_action: minimum_action.into(),
            reason_code: "native_test".into(),
            reason: "native test".into(),
            explicitly_benign: minimum_action == "allow",
        }
    }

    #[test]
    fn warning_policy_preserves_allow_with_warning() {
        let result = apply_pre_tool_policy(
            &snapshot(policy("warn")),
            &Value::Object(Map::new()),
            generic_result("allow"),
        )
        .unwrap();
        assert_eq!(result.minimum_action, "warn");
        assert_eq!(result.policy_action, "warn");
        assert_eq!(result.decision, "allow");
        assert!(!result.explicitly_benign);
    }

    #[test]
    fn observe_pre_policy_floor_is_non_blocking_but_intrinsic_block_is_hard() {
        let mut observed_snapshot = snapshot(policy("block"));
        observed_snapshot.mode = "observe".into();
        let policy_only = apply_pre_tool_policy(
            &observed_snapshot,
            &Value::Object(Map::new()),
            generic_result("allow"),
        )
        .unwrap();
        assert_eq!(policy_only.minimum_action, "warn");
        assert_eq!(policy_only.decision, "allow");

        let intrinsic = apply_pre_tool_policy(
            &observed_snapshot,
            &Value::Object(Map::new()),
            generic_result("block"),
        )
        .unwrap();
        assert_eq!(intrinsic.minimum_action, "block");
        assert_eq!(intrinsic.decision, "deny");
    }

    #[test]
    fn observe_preserves_every_intrinsic_non_allow_pre_floor() {
        let mut observed_snapshot = snapshot(policy("block"));
        observed_snapshot.mode = "observe".into();
        for action in ["review", "require-reapproval", "sandbox-required", "block"] {
            let intrinsic = apply_pre_tool_policy(
                &observed_snapshot,
                &Value::Object(Map::new()),
                generic_result(action),
            )
            .unwrap();
            assert_eq!(intrinsic.minimum_action, action);
            assert_eq!(intrinsic.decision, "deny");
            assert_eq!(intrinsic.reason_code, "native_test");
        }

        let mut malformed = generic_result("block");
        malformed.action.action_type = PreToolActionTypeV1::Unknown;
        malformed.reason_code = "native_pre_tool_malformed_payload".into();
        let malformed =
            apply_pre_tool_policy(&observed_snapshot, &Value::Object(Map::new()), malformed)
                .unwrap();
        assert_eq!(malformed.minimum_action, "block");
        assert_eq!(malformed.decision, "deny");
        assert_eq!(malformed.reason_code, "native_pre_tool_malformed_payload");
    }

    fn post_request(payload: Value) -> NativeHookRequestV1 {
        NativeHookRequestV1 {
            protocol_version: NATIVE_PROTOCOL_VERSION,
            request_id: Some("policy-test".into()),
            harness: "claude-code".into(),
            event_name: "PostToolUse".into(),
            payload,
            cwd: None,
            home_dir: "/home/test".into(),
            guard_home: "/home/test/.hol-guard".into(),
            source_ref_external_allowed: false,
            observe_mode: false,
            deadline_budget_ms: Some(750),
        }
    }

    #[test]
    fn policy_allow_cannot_lower_intrinsic_review_or_block() {
        let snapshot = snapshot(policy("allow"));
        for action in ["review", "block"] {
            let result = apply_pre_tool_policy(
                &snapshot,
                &Value::Object(Map::new()),
                generic_result(action),
            )
            .unwrap();
            assert_eq!(result.minimum_action, action);
            assert_eq!(result.decision, "deny");
        }
    }

    #[test]
    fn policy_block_raises_intrinsic_allow() {
        let snapshot = snapshot(policy("block"));
        let result = apply_pre_tool_policy(
            &snapshot,
            &Value::Object(Map::new()),
            generic_result("allow"),
        )
        .unwrap();
        assert_eq!(result.minimum_action, "block");
        assert_eq!(result.reason_code, "native_policy_block");
    }

    #[test]
    fn conflicting_harness_aliases_fail_closed() {
        let mut effective = policy("allow");
        effective
            .harness_actions
            .insert("claude".into(), "review".into());
        effective
            .harness_actions
            .insert("claude-code".into(), "block".into());
        let result = apply_pre_tool_policy(
            &snapshot(effective),
            &Value::Object(Map::new()),
            generic_result("allow"),
        );
        assert_eq!(
            result.unwrap_err(),
            "native_policy_harness_selector_conflict"
        );
    }

    #[test]
    fn conflicting_harness_risk_aliases_fail_closed() {
        let mut effective = policy("allow");
        effective.harness_risk_actions.insert(
            "claude".into(),
            BTreeMap::from([(String::from("execution"), String::from("review"))]),
        );
        effective.harness_risk_actions.insert(
            "claude-code".into(),
            BTreeMap::from([(String::from("execution"), String::from("block"))]),
        );
        let result = apply_pre_tool_policy(
            &snapshot(effective),
            &Value::Object(Map::new()),
            generic_result("allow"),
        );
        assert_eq!(
            result.unwrap_err(),
            "native_policy_harness_selector_conflict"
        );
    }

    #[test]
    fn post_intrinsic_block_cannot_be_lowered_by_allow_policy() {
        let request = post_request(json!({
            "tool_name": "read_file",
            "tool_response": "safe-looking output"
        }));
        let response =
            HookReviewResponseV1::deny("source_secret_match", "native source content was blocked");
        let result = apply_post_tool_policy(
            &snapshot(policy("allow")),
            &request,
            GuardHookPayloadKindV2::Inline,
            response,
        )
        .unwrap();
        assert_eq!(result.decision, "deny");
        assert_eq!(result.policy_action.as_deref(), Some("block"));
        let encoded = serde_json::to_string(&result).unwrap();
        assert!(!encoded.contains("safe-looking"));
    }

    #[test]
    fn post_warning_policy_preserves_allow_with_warning() {
        let request = post_request(json!({
            "tool_name": "read_file",
            "tool_response": "safe-looking output"
        }));
        let result = apply_post_tool_policy(
            &snapshot(policy("warn")),
            &request,
            GuardHookPayloadKindV2::Inline,
            HookReviewResponseV1::allow("output_scan_allow"),
        )
        .unwrap();
        assert_eq!(result.decision, "allow");
        assert_eq!(result.policy_action.as_deref(), Some("warn"));
        assert_eq!(result.notice, "warning");
    }

    #[test]
    fn post_policy_fields_raise_without_python_semantic_input() {
        let mut effective = policy("allow");
        effective.unknown_publisher_action = "review".into();
        effective.changed_hash_action = "block".into();
        effective
            .publisher_actions
            .insert("trusted".into(), "allow".into());
        effective
            .artifact_actions
            .insert("pkg-a".into(), "block".into());
        let request = post_request(json!({
            "tool_name": "npm_install",
            "publisher": "trusted",
            "artifact_id": "pkg-a",
            "changed": true,
            "tool_response": "ok"
        }));
        let result = apply_post_tool_policy(
            &snapshot(effective),
            &request,
            GuardHookPayloadKindV2::Inline,
            HookReviewResponseV1::allow("output_scan_allow"),
        )
        .unwrap();
        assert_eq!(result.decision, "deny");
        assert_eq!(result.policy_action.as_deref(), Some("block"));
    }

    #[test]
    fn unknown_post_action_is_review_even_when_default_allows() {
        let request = post_request(json!({
            "tool_name": "future_tool_v9",
            "tool_response": "ok"
        }));
        let result = apply_post_tool_policy(
            &snapshot(policy("allow")),
            &request,
            GuardHookPayloadKindV2::Inline,
            HookReviewResponseV1::allow("output_scan_allow"),
        )
        .unwrap();
        assert_eq!(result.decision, "deny");
        assert_eq!(result.policy_action.as_deref(), Some("review"));
        assert_eq!(result.reason_code, "native_policy_review_required");
    }

    #[test]
    fn conflicting_request_selectors_fail_closed() {
        let request = post_request(json!({
            "tool_name": "read_file",
            "publisher": "one",
            "publisherId": "two",
            "tool_response": "ok"
        }));
        let result = apply_post_tool_policy(
            &snapshot(policy("allow")),
            &request,
            GuardHookPayloadKindV2::Inline,
            HookReviewResponseV1::allow("output_scan_allow"),
        );
        assert_eq!(result.unwrap_err(), "native_policy_selector_conflict");
    }

    #[test]
    fn observe_preserves_intrinsic_block_but_does_not_enforce_policy_only_floor() {
        let request = post_request(json!({
            "tool_name": "read_file",
            "tool_response": "ok"
        }));
        let mut observed_snapshot = snapshot(policy("block"));
        observed_snapshot.mode = "observe".into();
        let policy_only = apply_post_tool_policy(
            &observed_snapshot,
            &request,
            GuardHookPayloadKindV2::Inline,
            HookReviewResponseV1::allow("output_scan_allow"),
        )
        .unwrap();
        assert_eq!(policy_only.decision, "allow");
        assert_eq!(policy_only.policy_action.as_deref(), Some("block"));

        let intrinsic_observed =
            HookReviewResponseV1::deny("source_secret_match", "blocked").observed(None);
        let intrinsic = apply_post_tool_policy(
            &observed_snapshot,
            &request,
            GuardHookPayloadKindV2::Inline,
            intrinsic_observed,
        )
        .unwrap();
        assert_eq!(intrinsic.decision, "deny");
        assert_eq!(intrinsic.policy_action.as_deref(), Some("block"));
        assert!(intrinsic.observe_mode);
    }
}
