//! The approval request a reviewed `PreToolUse` queues.
//!
//! This ports `queue_native_pre_tool_review` (`hook_native_review_approval.py`)
//! up to persistence: the tool name and launch target, the presentation
//! envelope with the exact-action keys, and every `GuardApprovalRequest`
//! field in its `to_dict` shape, ready for `add_native_review_approval_request`.
//! The envelope reads the host facts the daemon published (its environment
//! and working directory), never the resident's own process state. Any shape
//! whose answer could differ from the daemon's returns `None`, so the daemon
//! queues it instead.

use super::query::{pre_tool_command, pre_tool_input, strip, tool_name};
use guard_command::hook_adapter_envelope::{
    normalize_harness_envelope, EnvelopeRequest, IntentSummary,
};
use guard_command::hook_adapter_paths::PathEnv;
use guard_command::hook_adapter_value::{OMap, OValue};
use guard_command::hook_responses::Object;
use guard_command::package_intent_parser::parse_package_intent;
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;
use std::path::Path;

const DEFAULT_REASON: &str = "HOL Guard requires review before this action can execute.";
const LAUNCH_TARGET_FIELDS: [&str; 4] = ["url", "path", "file_path", "target"];
const EXACT_ACTION_CONTEXT_TOKEN_KEY: &str = "exact_context_token";
const EXACT_ACTION_IDENTITY_KIND_KEY: &str = "exact_identity_kind";
const ONCE_ONLY_REASON_KEY: &str = "once_only_reason";
/// `_ENVELOPE_KEYS`: the adapter answer Python accepts, and nothing else.
const ENVELOPE_KEYS: [&str; 23] = [
    "action_id",
    "action_type",
    "command",
    "command_category",
    "event_name",
    "harness",
    "mcp_server",
    "mcp_tool",
    "network_hosts",
    "package_intent_kind",
    "package_manager",
    "package_name",
    "package_targets",
    "pre_execution_result",
    "prompt_excerpt",
    "prompt_text",
    "raw_payload_redacted",
    "schema_version",
    "script_name",
    "target_paths",
    "tool_name",
    "workspace",
    "workspace_hash",
];
const ENVELOPE_LISTS: [&str; 3] = ["network_hosts", "package_targets", "target_paths"];
const ACTION_TYPES: [&str; 10] = [
    "prompt",
    "shell_command",
    "file_read",
    "file_write",
    "mcp_tool",
    "package_script",
    "network_request",
    "config_change",
    "browser_action",
    "harness_start",
];
/// Payload keys whose map order picks the envelope's MCP server; the
/// resident's payload is key-sorted, so these defer.
const ORDERED_SERVER_FIELDS: [&str; 3] = ["mcp_servers", "mcpServers", "servers"];
/// Tool-input keys that carry nothing but the shell command
/// (`_COMMAND_ONLY_INPUT_KEYS`).
const COMMAND_ONLY_INPUT_KEYS: [&str; 12] = [
    "command",
    "cmd",
    "shell_command",
    "shellCommand",
    "description",
    "timeout",
    "timeout_ms",
    "timeoutMs",
    "run_in_background",
    "runInBackground",
    "workdir",
    "cwd",
];
/// Far under the adapter's 1 MiB string slot and 4 MiB request cap, so the
/// daemon's adapter call cannot fail on a size the resident accepted.
const MAX_PAYLOAD_BYTES: usize = 256 * 1024;

/// What the exact-action query settled for the review.
pub(super) enum ExactKeys<'a> {
    Token(&'a str),
    OnceOnly(&'a str),
    /// No exact-action query. The daemon records such reviews; the resident
    /// queues only reviews it queried.
    #[cfg_attr(not(test), allow(dead_code))]
    Neither,
}

/// The request facts outside the edge result.
pub(super) struct RequestInput<'a> {
    pub(super) harness: &'a str,
    /// The payload the daemon records: without `hook_env`, with the execution
    /// environment field.
    pub(super) payload: &'a Map<String, Value>,
    pub(super) workspace: &'a str,
    pub(super) home_dir: &'a str,
    pub(super) environment: &'a BTreeMap<String, String>,
    pub(super) host_cwd: Option<&'a str>,
    pub(super) request_id: &'a str,
    pub(super) approval_center_url: &'a str,
    pub(super) review_binding: Option<&'a str>,
    pub(super) exact: ExactKeys<'a>,
}

/// The daemon's `action_envelope` adapter query for this review.
#[derive(Debug)]
pub(super) struct EnvelopeQuery<'a> {
    pub(super) workspace: &'a str,
    pub(super) home_dir: &'a str,
    pub(super) devin_project_dir: Option<&'a str>,
    pub(super) path_env: Option<&'a str>,
    pub(super) host: PathEnv,
}

/// `GuardApprovalRequest(...).to_dict()` for a reviewed `PreToolUse`.
pub(super) fn build(
    input: &RequestInput<'_>,
    result: &Object,
    receipt: Option<&Value>,
) -> Option<Value> {
    let query = envelope_query(input)?;
    let envelope = adapter_envelope(input, &query)?;
    finish(input, result, receipt, envelope)
}

/// The adapter query fields the daemon derives from its own process.
pub(super) fn envelope_query<'a>(input: &RequestInput<'a>) -> Option<EnvelopeQuery<'a>> {
    // An empty workspace scopes the request to the harness and Guard home,
    // which the daemon fills in.
    if input.workspace.is_empty() {
        return None;
    }
    let text = |name: &str| {
        input
            .environment
            .get(name)
            .map(String::as_str)
            .filter(|value| !value.is_empty())
    };
    let tilde_home = expanded_home(input.environment)?;
    let resolved = (!tilde_home.starts_with('~')).then_some(tilde_home);
    Some(EnvelopeQuery {
        workspace: input.workspace,
        home_dir: input.home_dir,
        devin_project_dir: text("DEVIN_PROJECT_DIR"),
        path_env: text("PATH"),
        host: PathEnv {
            tilde_home: resolved.clone(),
            default_home: resolved,
            cwd: input.host_cwd.map(str::to_owned),
        },
    })
}

/// `os.path.expanduser("~")` in the daemon's published environment. Without
/// `HOME` it reads the password database, which that environment cannot
/// answer.
#[cfg(unix)]
fn expanded_home(environment: &BTreeMap<String, String>) -> Option<String> {
    let trimmed = environment.get("HOME")?.trim_end_matches('/');
    Some(if trimmed.is_empty() { "/" } else { trimmed }.to_owned())
}

/// `ntpath.expanduser("~")`: `USERPROFILE` as it stands, else
/// `ntpath.join(HOMEDRIVE, HOMEPATH)`. `os.environ` spells Windows names in
/// upper case, as published.
#[cfg(windows)]
fn expanded_home(environment: &BTreeMap<String, String>) -> Option<String> {
    if let Some(profile) = environment.get("USERPROFILE") {
        return Some(profile.clone());
    }
    let drive = environment.get("HOMEDRIVE").map_or("", String::as_str);
    join_home_drive(drive, environment.get("HOMEPATH")?)
}

/// `ntpath.join(drive, path)` where it is plain concatenation: an empty or
/// letter drive, and a path that names no drive and does not start a UNC
/// share. Other shapes go through `splitroot`, so the daemon joins them.
#[cfg(any(windows, test))]
fn join_home_drive(drive: &str, path: &str) -> Option<String> {
    let letter_drive = matches!(drive.as_bytes(), [letter, b':'] if letter.is_ascii_alphabetic());
    let separators = path
        .bytes()
        .take_while(|byte| matches!(byte, b'\\' | b'/'))
        .count();
    ((drive.is_empty() || letter_drive) && !path.contains(':') && separators < 2)
        .then(|| format!("{drive}{path}"))
}

#[cfg(not(any(unix, windows)))]
fn expanded_home(_environment: &BTreeMap<String, String>) -> Option<String> {
    None
}

/// `native_action_envelope`, run in process.
fn adapter_envelope(input: &RequestInput<'_>, query: &EnvelopeQuery<'_>) -> Option<Value> {
    // The resident's payload map is key-sorted, while the daemon's keeps the
    // hook's order. Cline preparation and server maps read keys in order;
    // every other adapter step looks keys up or sorts them first.
    if input.harness == "cline"
        || ORDERED_SERVER_FIELDS
            .iter()
            .any(|field| input.payload.get(*field).is_some_and(Value::is_object))
    {
        return None;
    }
    let encoded = serde_json::to_vec(input.payload).ok()?;
    if encoded.len() > MAX_PAYLOAD_BYTES {
        return None;
    }
    let payload = match OValue::from_wire(&tagged(&Value::Object(input.payload.clone()))).ok()? {
        OValue::Map(map) => map,
        _ => return None,
    };
    let environment: Option<BTreeMap<String, String>> = query
        .path_env
        .map(|path| BTreeMap::from([("PATH".to_owned(), path.to_owned())]));
    let mut provider = |command: &str, workspace: Option<&Path>, home: Option<&Path>| {
        parse_package_intent(command, workspace, home, None, environment.as_ref()).map(|intent| {
            IntentSummary {
                package_manager: intent.package_manager,
                intent_kind: intent.intent_kind.to_owned(),
                targets: intent
                    .targets
                    .into_iter()
                    .map(|target| (target.raw_spec, target.package_name))
                    .collect(),
            }
        })
    };
    let request = EnvelopeRequest {
        harness: input.harness,
        event_name: "PreToolUse",
        payload: &payload,
        workspace: Some(query.workspace),
        home_dir: Some(query.home_dir),
        devin_project_dir: query.devin_project_dir,
        env: query.host.clone(),
    };
    let envelope: OMap = normalize_harness_envelope(&request, &mut provider).ok()?;
    serde_json::from_str(&OValue::Map(envelope).compact_json()).ok()
}

/// The plain JSON `value` in the adapter's tagged wire form.
fn tagged(value: &Value) -> Value {
    match value {
        Value::Array(items) => {
            let mut wire = vec![Value::String("l".to_owned())];
            wire.extend(items.iter().map(tagged));
            Value::Array(wire)
        }
        Value::Object(fields) => {
            let mut wire = vec![Value::String("d".to_owned())];
            for (key, item) in fields {
                wire.push(Value::String(key.clone()));
                wire.push(tagged(item));
            }
            Value::Array(wire)
        }
        scalar => scalar.clone(),
    }
}

/// The request around the adapter's envelope answer.
pub(super) fn finish(
    input: &RequestInput<'_>,
    result: &Object,
    receipt: Option<&Value>,
    envelope: Value,
) -> Option<Value> {
    if input.workspace.is_empty()
        || !policy_binding_valid(result, receipt)
        || allow_hint_candidate(input.payload, result)?
    {
        return None;
    }
    let tool_name = tool_name(input.payload).ok()?;
    let command = pre_tool_command(input.payload).ok()?;
    let launch_target = launch_target(input.payload, command.as_deref(), &tool_name)?;
    let reason = match result.get("reason") {
        None | Some(Value::Null) => DEFAULT_REASON.to_owned(),
        Some(Value::String(text)) if text.is_empty() => DEFAULT_REASON.to_owned(),
        Some(Value::String(text)) => text.clone(),
        Some(_) => return None,
    };
    let mut envelope = review_envelope(envelope)?;
    if let Some(receipt) = receipt
        .and_then(Value::as_object)
        .filter(|receipt| receipt.contains_key("origin_authentication"))
    {
        envelope.insert(
            "native_origin_receipt".to_owned(),
            Value::Object(receipt.clone()),
        );
    }
    match input.exact {
        ExactKeys::Token(token) => {
            envelope.insert(EXACT_ACTION_CONTEXT_TOKEN_KEY.to_owned(), json!(token));
            if command.is_none() {
                envelope.insert(
                    EXACT_ACTION_IDENTITY_KIND_KEY.to_owned(),
                    json!("tool-target"),
                );
            }
        }
        ExactKeys::OnceOnly(reason) => {
            envelope.insert(ONCE_ONLY_REASON_KEY.to_owned(), json!(reason));
        }
        ExactKeys::Neither => {}
    }
    let request_id = input.request_id;
    Some(json!({
        "request_id": request_id,
        "harness": input.harness,
        "artifact_id": format!("{}:native-pretool:{tool_name}", input.harness),
        "artifact_name": tool_name,
        "artifact_hash": input.review_binding.filter(|binding| !binding.is_empty()).unwrap_or(request_id),
        "policy_action": "review",
        "recommended_scope": "artifact",
        "changed_fields": ["native_pre_tool"],
        "source_scope": "project",
        "config_path": input.workspace,
        "review_command": format!("hol-guard approvals approve {request_id}"),
        "approval_url": format!("{}/requests/{request_id}", input.approval_center_url),
        "workspace": input.workspace,
        "artifact_type": "tool_call",
        "launch_target": launch_target,
        "transport": null,
        "publisher": null,
        "risk_summary": reason,
        "risk_signals": [],
        "artifact_label": null,
        "source_label": null,
        "trigger_summary": null,
        "why_now": null,
        "launch_summary": null,
        "risk_headline": null,
        "action_envelope_json": envelope,
        "decision_v2_json": null,
        "fallback_cli_command": null,
        "action_identity": null,
        "queue_group_id": null,
        "dedupe_count": 1,
        "last_seen_at": null,
        "scanner_evidence": [],
        "browser_intent": null,
        "raw_command_text": command,
        "guard_version": null,
        "first_seen_guard_version": null,
        "last_seen_guard_version": null,
        "continuation_snapshot": null,
        "extension_allow_hint": null,
    }))
}

/// `_envelope_from_native(...).with_pre_execution_result("review").to_dict()`,
/// for an answer whose fields already have their typed shapes.
fn review_envelope(envelope: Value) -> Option<Map<String, Value>> {
    let Value::Object(mut envelope) = envelope else {
        return None;
    };
    if envelope.len() != ENVELOPE_KEYS.len()
        || ENVELOPE_KEYS.iter().any(|key| !envelope.contains_key(*key))
    {
        return None;
    }
    let typed = envelope.iter().all(|(key, value)| match key.as_str() {
        "schema_version" => value.as_i64().is_some(),
        "action_id" => value.as_str().is_some_and(|text| !text.is_empty()),
        "harness" | "event_name" => value.is_string(),
        "action_type" => value
            .as_str()
            .is_some_and(|kind| ACTION_TYPES.contains(&kind)),
        "raw_payload_redacted" => value.is_object(),
        key if ENVELOPE_LISTS.contains(&key) => value
            .as_array()
            .is_some_and(|items| items.iter().all(Value::is_string)),
        _ => value.is_null() || value.is_string(),
    });
    if !typed {
        return None;
    }
    envelope.insert("pre_execution_result".to_owned(), json!("review"));
    Some(envelope)
}

/// `native_review_policy_binding` for the edge's own receipt, which matches
/// the edge result by construction: a command-extension review needs the
/// typed binding facts, or the daemon creates no approval.
fn policy_binding_valid(result: &Object, receipt: Option<&Value>) -> bool {
    let receipt = receipt.and_then(Value::as_object);
    let receipt_bound = receipt.is_some_and(|receipt| receipt.contains_key("command_extensions"));
    if !result.contains_key("command_extensions") && !receipt_bound {
        return true;
    }
    let Some(receipt) = receipt else {
        return false;
    };
    let digests = ["policy_digest", "rule_digest", "runtime_identity"]
        .iter()
        .all(|field| receipt.get(*field).is_some_and(Value::is_string));
    let count = receipt
        .get("command_extensions")
        .and_then(Value::as_object)
        .and_then(|binding| binding.get("uncertainty_count"));
    digests
        && count.is_some_and(|count| count.as_u64().is_some() && !count.to_string().contains('.'))
}

/// `_native_review_launch_target`.
fn launch_target(
    payload: &Map<String, Value>,
    command: Option<&str>,
    tool_name: &str,
) -> Option<String> {
    if let Some(command) = command {
        return Some(command.to_owned());
    }
    if let Some(tool_input) = pre_tool_input(payload) {
        for key in LAUNCH_TARGET_FIELDS {
            if let Some(value) = tool_input.get(key).and_then(Value::as_str) {
                if let Some(stripped) = strip(value).ok()? {
                    return Some(stripped.to_owned());
                }
            }
        }
    }
    Some(format!("tool:{tool_name}"))
}

/// Whether `native_review_extension_allow_hint` could store a hint: a
/// definite extension review of a command-only shell call. The resident does
/// not run that re-review, so these defer.
pub(super) fn allow_hint_candidate(payload: &Map<String, Value>, result: &Object) -> Option<bool> {
    if result.get("minimum_action").and_then(Value::as_str) != Some("review") {
        return Some(false);
    }
    let Some(evidence) = result.get("command_extensions").and_then(Value::as_object) else {
        return Some(false);
    };
    if evidence.get("evaluation_error").is_some_and(truthy) {
        return Some(false);
    }
    let Some(binding) = evidence.get("binding").and_then(Value::as_object) else {
        return Some(false);
    };
    // Python compares `!= 0`, which `False` and `0.0` also pass.
    let certain = match binding.get("uncertainty_count") {
        Some(Value::Bool(flag)) => !flag,
        Some(Value::Number(count)) => count.as_f64() == Some(0.0),
        _ => false,
    };
    if !certain
        || !binding
            .get("observations_digest")
            .is_some_and(Value::is_string)
    {
        return Some(false);
    }
    if pre_tool_command(payload).ok()?.is_none() {
        return Some(false);
    }
    let Some(tool_input) = pre_tool_input(payload) else {
        return Some(false);
    };
    Some(
        tool_input
            .keys()
            .all(|key| COMMAND_ONLY_INPUT_KEYS.contains(&key.as_str())),
    )
}

/// Python truthiness for a JSON value.
fn truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(flag) => *flag,
        Value::Number(number) => number.as_f64().is_some_and(|value| value != 0.0),
        Value::String(text) => !text.is_empty(),
        Value::Array(items) => !items.is_empty(),
        Value::Object(fields) => !fields.is_empty(),
    }
}

#[cfg(test)]
#[path = "hook_direct_review_request_tests.rs"]
mod tests;
