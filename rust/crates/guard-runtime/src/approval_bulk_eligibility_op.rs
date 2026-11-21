//! `ApprovalBulkEligibility` - resident op that decides whether pending
//! approval requests may be approved once through the bulk flow.
//!
//! Pure: the caller ships the stored request fields and receives one boolean
//! per request. A request is bulk-eligible only when it is pending, not
//! blocked by policy, not a sensitive file read, and carries no catastrophic
//! decision category or command hint.

use std::path::{Component, Path, PathBuf};
use std::sync::OnceLock;

use guard_command::secret_path_probe::is_secret_path;
use guard_contracts::{
    ApprovalBulkEligibilityItemV1, ApprovalBulkEligibilityRequestV1,
    ApprovalBulkEligibilityResultV1, APPROVAL_BULK_ELIGIBILITY_MAX_BYTES,
    APPROVAL_BULK_ELIGIBILITY_MAX_ITEMS, APPROVAL_BULK_ELIGIBILITY_RESULT_SCHEMA,
};
use regex::Regex;
use serde_json::{json, Map, Value};

use crate::approval_queue_identity_op::{is_truthy, py_str};
use crate::package_authority_op::request_digest_with_limit;
use crate::policy_bundle_py::is_py_space;

const SECRET_TEXT_HINTS: [&str; 11] = [
    "credential",
    "secret",
    ".env",
    "token",
    "api key",
    "apikey",
    "password",
    "private key",
    "ssh key",
    "aws_access_key",
    "github_token",
];
const SECRET_PATH_TEXT_HINTS: [&str; 7] = [
    ".env",
    "token",
    "secret",
    "credential",
    "password",
    "private key",
    "api key",
];
const BLOCKED_DECISION_CATEGORIES: [&str; 6] = [
    "secret",
    "credential",
    "bypass",
    "prompt_injection",
    "system_prompt",
    "encoded",
];
const BLOCKED_COMMAND_HINTS: [&str; 18] = [
    "prompt injection",
    "ignore previous",
    "disregard previous",
    "override instruction",
    "bypass guard",
    "disable guard",
    "skip approval",
    "ignore approval",
    "without approval",
    "guard_bypass",
    "no guard",
    "base64",
    "openssl enc",
    "xxd -r",
    "decode-and-exec",
    "exfiltrat",
    "clipboard",
    "pastebin",
];
const READ_COMMANDS: [&str; 8] = ["cat", "grep", "rg", "awk", "less", "more", "head", "tail"];
const CATEGORY_ENVELOPE_KEYS: [&str; 9] = [
    "action_type",
    "command",
    "tool_name",
    "prompt_excerpt",
    "mcp_server",
    "mcp_tool",
    "package_manager",
    "package_name",
    "script_name",
];
const ACTION_ENVELOPE_KEYS: [&str; 8] = [
    "command",
    "prompt_text",
    "prompt_excerpt",
    "mcp_server",
    "mcp_tool",
    "package_manager",
    "package_name",
    "script_name",
];

pub(crate) fn evaluate_approval_bulk_eligibility_request(
    request: &ApprovalBulkEligibilityRequestV1,
) -> Result<Vec<u8>, String> {
    let request_sha256 = request_digest_with_limit(request, APPROVAL_BULK_ELIGIBILITY_MAX_BYTES)
        .map_err(|_| "native_approval_bulk_eligibility_too_large".to_owned())?;
    let (status, code, payload) = match evaluate(request) {
        Ok(payload) => ("ok".to_owned(), "ok".to_owned(), Some(payload)),
        Err(code) => ("error".to_owned(), code, None),
    };
    crate::encode_response(&ApprovalBulkEligibilityResultV1 {
        schema: APPROVAL_BULK_ELIGIBILITY_RESULT_SCHEMA.to_owned(),
        request_id: request.request_id.clone(),
        request_sha256,
        status,
        code,
        payload,
    })
}

pub(crate) fn evaluate(request: &ApprovalBulkEligibilityRequestV1) -> Result<Value, String> {
    if request.items.len() > APPROVAL_BULK_ELIGIBILITY_MAX_ITEMS {
        return Err("native_approval_bulk_eligibility_too_large".to_owned());
    }
    let home = request.home_dir.as_deref().map(Path::new);
    let items: Vec<Value> = request
        .items
        .iter()
        .map(|item| json!({ "eligible": is_eligible(item, home) }))
        .collect();
    Ok(json!({ "items": items }))
}

/// A field that cannot be rendered as scalar text (a list or object where the
/// store keeps text). The request is judged ineligible and reviewed alone.
struct Unrenderable;

/// Python `str(value or "")`.
fn text_of(value: Option<&Value>) -> Result<String, Unrenderable> {
    match value {
        None => Ok(String::new()),
        Some(value) if !is_truthy(value) => Ok(String::new()),
        Some(value) => py_str(value).ok_or(Unrenderable),
    }
}

/// A non-empty string field, as `isinstance(value, str) and value`.
fn non_empty_text(value: Option<&Value>) -> Option<&str> {
    match value {
        Some(Value::String(text)) if !text.is_empty() => Some(text),
        _ => None,
    }
}

fn envelope_of(item: &ApprovalBulkEligibilityItemV1) -> Option<&Map<String, Value>> {
    item.action_envelope_json.as_ref()?.as_object()
}

fn target_path_texts(envelope: &Map<String, Value>) -> Vec<&str> {
    match envelope.get("target_paths") {
        Some(Value::Array(paths)) => paths.iter().filter_map(Value::as_str).collect(),
        _ => Vec::new(),
    }
}

fn string_items(value: Option<&Value>) -> Vec<&str> {
    match value {
        Some(Value::Array(items)) => items.iter().filter_map(Value::as_str).collect(),
        _ => Vec::new(),
    }
}

/// `_bulk_queue_category_text`.
fn category_text(item: &ApprovalBulkEligibilityItemV1) -> Result<String, Unrenderable> {
    let mut fields: Vec<String> = Vec::new();
    if let Some(envelope) = envelope_of(item) {
        for key in CATEGORY_ENVELOPE_KEYS {
            if let Some(text) = non_empty_text(envelope.get(key)) {
                fields.push(text.to_owned());
            }
        }
        fields.extend(target_path_texts(envelope).into_iter().map(str::to_owned));
        if let Some(Value::Array(signals)) = envelope.get("signals") {
            for signal in signals.iter().filter_map(Value::as_object) {
                for key in ["category", "title", "plain_reason"] {
                    if let Some(text) = non_empty_text(signal.get(key)) {
                        fields.push(text.to_owned());
                    }
                }
            }
        }
    }
    let mut parts = vec![
        text_of(item.artifact_name.as_ref())?,
        text_of(item.artifact_type.as_ref())?,
        text_of(item.risk_headline.as_ref())?,
        text_of(item.risk_summary.as_ref())?,
        text_of(item.trigger_summary.as_ref())?,
        text_of(item.launch_summary.as_ref())?,
        text_of(item.why_now.as_ref())?,
        text_of(item.launch_target.as_ref())?,
    ];
    parts.extend(
        string_items(item.risk_signals.as_ref())
            .into_iter()
            .map(str::to_owned),
    );
    parts.extend(fields);
    Ok(parts.join(" "))
}

/// `_bulk_action_text`: user-supplied action text, never generated risk prose.
fn action_text(item: &ApprovalBulkEligibilityItemV1) -> Result<String, Unrenderable> {
    let mut fields: Vec<String> = Vec::new();
    if let Some(envelope) = envelope_of(item) {
        for key in ACTION_ENVELOPE_KEYS {
            if let Some(text) = non_empty_text(envelope.get(key)) {
                fields.push(text.to_owned());
            }
        }
        fields.extend(target_path_texts(envelope).into_iter().map(str::to_owned));
    }
    let mut parts = vec![
        text_of(item.artifact_name.as_ref())?,
        text_of(item.artifact_type.as_ref())?,
        text_of(item.raw_command_text.as_ref())?,
        text_of(item.launch_target.as_ref())?,
    ];
    parts.extend(fields);
    Ok(parts.join(" "))
}

/// `_bulk_decision_v2_categories`.
fn decision_categories(item: &ApprovalBulkEligibilityItemV1) -> Vec<&str> {
    let Some(Value::Object(decision)) = item.decision_v2_json.as_ref() else {
        return Vec::new();
    };
    match decision.get("signals") {
        Some(Value::Array(signals)) => signals
            .iter()
            .filter_map(Value::as_object)
            .filter_map(|signal| non_empty_text(signal.get("category")))
            .collect(),
        _ => Vec::new(),
    }
}

/// Python `\w`: a letter, a number or an underscore (combining marks are not).
fn is_word_char(character: char) -> bool {
    static WORD: OnceLock<Regex> = OnceLock::new();
    if character.is_ascii() {
        return character.is_ascii_alphanumeric() || character == '_';
    }
    let mut buffer = [0_u8; 4];
    WORD.get_or_init(|| Regex::new(r"^[\p{L}\p{N}_]$").expect("static pattern"))
        .is_match(character.encode_utf8(&mut buffer))
}

fn keyword_at(chars: &[char], start: usize, keyword: &str) -> Option<usize> {
    let mut end = start;
    for expected in keyword.chars() {
        if chars.get(end) != Some(&expected) {
            return None;
        }
        end += 1;
    }
    Some(end)
}

/// `sed\s+-n` starting at `start`; the end of the match.
fn sed_n_at(chars: &[char], start: usize) -> Option<usize> {
    let mut end = keyword_at(chars, start, "sed")?;
    let spaces_from = end;
    while chars
        .get(end)
        .is_some_and(|character| is_py_space(*character))
    {
        end += 1;
    }
    if end == spaces_from {
        return None;
    }
    keyword_at(chars, end, "-n")
}

/// `_bulk_read_command`: `\b(?:cat|grep|rg|sed\s+-n|awk|less|more|head|tail)\b`
/// over the lower-cased command.
fn is_read_command(command: &str) -> bool {
    let chars: Vec<char> = command.to_lowercase().chars().collect();
    (0..chars.len()).any(|start| {
        if start > 0 && is_word_char(chars[start - 1]) {
            return false;
        }
        let ends = READ_COMMANDS
            .iter()
            .filter_map(|keyword| keyword_at(&chars, start, keyword))
            .chain(sed_n_at(&chars, start));
        ends.into_iter()
            .any(|end| chars.get(end).is_none_or(|next| !is_word_char(*next)))
    })
}

fn contains_hint(text: &str, hints: &[&str]) -> bool {
    let lowered = text.to_lowercase();
    hints.iter().any(|hint| lowered.contains(hint))
}

/// Python `Path(workspace).expanduser()`.
fn workspace_dir(workspace: &str, home: Option<&Path>) -> PathBuf {
    let expanded = match (workspace, home) {
        ("~", Some(home)) => home.to_path_buf(),
        (text, Some(home)) if text.starts_with("~/") => home.join(&text[2..]),
        (text, _) => PathBuf::from(text),
    };
    let cleaned: PathBuf = expanded
        .components()
        .filter(|component| !matches!(component, Component::CurDir))
        .collect();
    if cleaned.as_os_str().is_empty() {
        PathBuf::from(".")
    } else {
        cleaned
    }
}

/// `_bulk_target_paths_are_secret`.
fn target_paths_are_secret(item: &ApprovalBulkEligibilityItemV1, home: Option<&Path>) -> bool {
    let Some(envelope) = envelope_of(item) else {
        return false;
    };
    let workspace = non_empty_text(envelope.get("workspace")).map(|text| workspace_dir(text, home));
    target_path_texts(envelope)
        .into_iter()
        .any(|path| is_secret_path(path, workspace.as_deref(), home))
}

/// `_bulk_is_file_read_request`.
fn is_file_read_request(
    item: &ApprovalBulkEligibilityItemV1,
    category: &str,
) -> Result<bool, Unrenderable> {
    let envelope = envelope_of(item);
    if envelope
        .and_then(|map| map.get("action_type"))
        .and_then(Value::as_str)
        == Some("file_read")
    {
        return Ok(true);
    }
    if text_of(item.artifact_type.as_ref())? == "file_read_request" {
        return Ok(true);
    }
    let mut command = match envelope {
        Some(map) => text_of(map.get("command"))?,
        None => String::new(),
    };
    if command.is_empty() {
        command = text_of(item.launch_target.as_ref())?;
    }
    Ok(is_read_command(&command) && contains_hint(category, &SECRET_PATH_TEXT_HINTS))
}

/// `not _bulk_request_is_bulk_blocked`.
fn is_eligible(item: &ApprovalBulkEligibilityItemV1, home: Option<&Path>) -> bool {
    judge(item, home).unwrap_or(false)
}

fn judge(item: &ApprovalBulkEligibilityItemV1, home: Option<&Path>) -> Result<bool, Unrenderable> {
    let policy_action = text_of(item.policy_action.as_ref())?;
    if policy_action == "block" || policy_action == "sandbox-required" {
        return Ok(false);
    }
    if text_of(item.status.as_ref())? != "pending" {
        return Ok(false);
    }
    let categories = decision_categories(item);
    let action = action_text(item)?;
    let category = category_text(item)?;
    if is_file_read_request(item, &category)?
        && (target_paths_are_secret(item, home)
            || categories.contains(&"secret")
            || contains_hint(&action, &SECRET_TEXT_HINTS))
    {
        return Ok(false);
    }
    if categories
        .iter()
        .any(|name| BLOCKED_DECISION_CATEGORIES.contains(name))
    {
        return Ok(false);
    }
    Ok(!contains_hint(&action, &BLOCKED_COMMAND_HINTS))
}

#[cfg(test)]
#[path = "approval_bulk_eligibility_vectors_tests.rs"]
mod vectors;
