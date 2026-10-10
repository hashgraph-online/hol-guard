//! `ApprovalQueueIdentity` - resident op that derives the queue identity of
//! approval requests: the normalized identity key, the action identity and the
//! queue group id that decide which pending approvals are duplicates.
//!
//! Pure: the caller ships the narrowed request fields and only uses the
//! returned identity as lookup material inside its own transaction.

use std::sync::OnceLock;

use guard_contracts::{
    python_float_repr, ApprovalQueueIdentityItemV1, ApprovalQueueIdentityRequestV1,
    ApprovalQueueIdentityResultV1, APPROVAL_QUEUE_IDENTITY_MAX_BYTES,
    APPROVAL_QUEUE_IDENTITY_MAX_ITEMS, APPROVAL_QUEUE_IDENTITY_RESULT_SCHEMA,
};
use regex::Regex;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::guard_store_json::{dumps_sorted, py_strip};
use crate::package_authority_op::request_digest_with_limit;

const INVALID: &str = "native_approval_queue_identity_invalid";
const IDENTITY_VERSION: &str = "v1";
const VOLATILE_PAYLOAD_KEY_TOKENS: [&str; 12] = [
    "callid",
    "conversationid",
    "messageid",
    "model",
    "requestid",
    "sessionid",
    "threadid",
    "toolcallid",
    "tooluseid",
    "traceid",
    "transcriptpath",
    "turnid",
];

pub(crate) fn evaluate_approval_queue_identity_request(
    request: &ApprovalQueueIdentityRequestV1,
) -> Result<Vec<u8>, String> {
    let request_sha256 = request_digest_with_limit(request, APPROVAL_QUEUE_IDENTITY_MAX_BYTES)
        .map_err(|_| "native_approval_queue_identity_too_large".to_owned())?;
    let (status, code, payload) = match evaluate(request) {
        Ok(payload) => ("ok".to_owned(), "ok".to_owned(), Some(payload)),
        Err(code) => ("error".to_owned(), code, None),
    };
    crate::encode_response(&ApprovalQueueIdentityResultV1 {
        schema: APPROVAL_QUEUE_IDENTITY_RESULT_SCHEMA.to_owned(),
        request_id: request.request_id.clone(),
        request_sha256,
        status,
        code,
        payload,
    })
}

pub(crate) fn evaluate(request: &ApprovalQueueIdentityRequestV1) -> Result<Value, String> {
    if request.items.len() > APPROVAL_QUEUE_IDENTITY_MAX_ITEMS {
        return Err("native_approval_queue_identity_too_large".to_owned());
    }
    let mut items = Vec::with_capacity(request.items.len());
    for item in &request.items {
        items.push(identify(item).ok_or_else(|| INVALID.to_owned())?);
    }
    Ok(json!({ "items": items }))
}

fn identify(item: &ApprovalQueueIdentityItemV1) -> Option<Value> {
    let identity_key = normalize_command_identity(item.launch_target.as_deref().unwrap_or(""));
    let action_identity = match item.action_identity.as_deref().filter(|id| !id.is_empty()) {
        Some(identity) => identity.to_owned(),
        None => build_action_identity(item.launch_target.as_deref(), item.envelope.as_ref())?,
    };
    let queue_group_id = match item.queue_group_id.as_deref().filter(|id| !id.is_empty()) {
        Some(group) => group.to_owned(),
        None => build_queue_group_id(item, &action_identity)?,
    };
    Some(json!({
        "identity_key": identity_key,
        "action_identity": action_identity,
        "queue_group_id": queue_group_id,
    }))
}

fn regex(cell: &'static OnceLock<Regex>, pattern: &str) -> &'static Regex {
    cell.get_or_init(|| Regex::new(pattern).expect("static pattern"))
}

/// Python `\s`: Unicode white space plus the C0 separators `str.isspace` adds.
const PY_SPACE: &str = r"[\s\x1c-\x1f]";

/// `normalize_command_identity`: strip ANSI codes, request ids, UUIDs,
/// timestamps and port flags, then collapse whitespace.
pub(crate) fn normalize_command_identity(command: &str) -> String {
    static ANSI: OnceLock<Regex> = OnceLock::new();
    static REQUEST_ID: OnceLock<Regex> = OnceLock::new();
    static UUID: OnceLock<Regex> = OnceLock::new();
    static TIMESTAMP: OnceLock<Regex> = OnceLock::new();
    static PORT: OnceLock<Regex> = OnceLock::new();
    static SPACE: OnceLock<Regex> = OnceLock::new();
    let text = regex(&ANSI, r"\x1b\[[0-9;]*[mABCDEFGHJKSTfhinsu]").replace_all(command, "");
    let text = regex(
        &REQUEST_ID,
        // Python `re.IGNORECASE` also folds the dotless and dotted i onto `i`.
        r"(?i)\b(?:req|request|approval|[iı\x{130}]d)[-_][a-zA-Z0-9_ı\x{130}-]{4,64}\b",
    )
    .replace_all(&text, "<request-id>");
    let text = regex(
        &UUID,
        r"\b[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\b",
    )
    .replace_all(&text, "<uuid>");
    let text = regex(
        &TIMESTAMP,
        r"\b\d{4}-\d{2}-\d{2}(?:T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2}))?\b",
    )
    .replace_all(&text, "<timestamp>");
    let text = regex(&PORT, &format!(r"(?i)(?:--port|-p){PY_SPACE}+\d{{2,5}}\b"))
        .replace_all(&text, "<port-flag>");
    let text = regex(&SPACE, &format!("{PY_SPACE}+")).replace_all(&text, " ");
    py_strip(&text).to_owned()
}

/// `_optional_text`: a non-blank string, stripped.
fn optional_text(value: Option<&Value>) -> Option<String> {
    match value {
        Some(Value::String(text)) if !py_strip(text).is_empty() => Some(py_strip(text).to_owned()),
        _ => None,
    }
}

/// `_string_sequence`: the non-blank string items of a list, sorted.
fn string_sequence(value: Option<&Value>) -> Vec<String> {
    let Some(Value::Array(items)) = value else {
        return Vec::new();
    };
    let mut texts: Vec<String> = items
        .iter()
        .filter_map(|item| match item {
            Value::String(text) if !py_strip(text).is_empty() => Some(text.clone()),
            _ => None,
        })
        .collect();
    texts.sort();
    texts
}

/// `_identity_payload_key_token`.
fn key_token(key: &str) -> String {
    key.to_lowercase()
        .chars()
        .filter(|character| character.is_ascii_lowercase() || character.is_ascii_digit())
        .collect()
}

/// `_stable_identity_payload`: drop volatile keys at every depth.
fn stable_identity_payload(value: &Value) -> Value {
    match value {
        Value::Object(entries) => Value::Object(
            entries
                .iter()
                .filter(|(key, _)| !VOLATILE_PAYLOAD_KEY_TOKENS.contains(&key_token(key).as_str()))
                .map(|(key, item)| (key.clone(), stable_identity_payload(item)))
                .collect::<Map<String, Value>>(),
        ),
        Value::Array(items) => Value::Array(items.iter().map(stable_identity_payload).collect()),
        other => other.clone(),
    }
}

/// `_build_action_identity`.
fn build_action_identity(launch_target: Option<&str>, envelope: Option<&Value>) -> Option<String> {
    let empty = Map::new();
    let envelope = match envelope {
        None | Some(Value::Null) => &empty,
        Some(Value::Object(map)) => map,
        Some(_) => return None,
    };
    let command = optional_text(envelope.get("command"))
        .or_else(|| {
            launch_target
                .filter(|target| !target.is_empty())
                .map(str::to_owned)
        })
        .unwrap_or_default();
    let payload = json!({
        "version": IDENTITY_VERSION,
        "action_type": optional_text(envelope.get("action_type")),
        "tool_name": optional_text(envelope.get("tool_name")),
        "command": normalize_command_identity(&command),
        "prompt_excerpt": optional_text(envelope.get("prompt_excerpt")),
        "target_paths": string_sequence(envelope.get("target_paths")),
        "network_hosts": string_sequence(envelope.get("network_hosts")),
        "mcp_server": optional_text(envelope.get("mcp_server")),
        "mcp_tool": optional_text(envelope.get("mcp_tool")),
        "package_manager": Value::Null,
        "package_name": Value::Null,
        "script_name": optional_text(envelope.get("script_name")),
        "raw_payload_redacted": envelope
            .get("raw_payload_redacted")
            .map_or(Value::Null, stable_identity_payload),
    });
    dumps_sorted(&payload)
}

/// Python `str(value)` for the scalar JSON values a browser intent holds.
fn py_str(value: &Value) -> Option<String> {
    match value {
        Value::String(text) => Some(text.clone()),
        Value::Null => Some("None".to_owned()),
        Value::Bool(flag) => Some(if *flag { "True" } else { "False" }.to_owned()),
        Value::Number(number) => {
            let raw = number.as_str();
            if raw.bytes().any(|byte| matches!(byte, b'.' | b'e' | b'E')) {
                let float = number.as_f64()?;
                float.is_finite().then(|| python_float_repr(float))
            } else {
                Some(if raw == "-0" { "0" } else { raw }.to_owned())
            }
        }
        Value::Array(_) | Value::Object(_) => None,
    }
}

fn is_truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(flag) => *flag,
        Value::Number(number) => number.as_f64().is_none_or(|float| float != 0.0),
        Value::String(text) => !text.is_empty(),
        Value::Array(items) => !items.is_empty(),
        Value::Object(entries) => !entries.is_empty(),
    }
}

/// `normalize_browser_mcp_identity`.
fn browser_identity_hash(intent: &Value) -> Option<String> {
    let call = intent.as_object()?;
    let field = |key: &str, default: &str| -> Option<String> {
        call.get(key)
            .map_or_else(|| Some(default.to_owned()), py_str)
    };
    let field_or = |key: &str, fallback: &str| -> Option<String> {
        match call.get(key) {
            Some(value) => py_str(value),
            None => field(fallback, ""),
        }
    };
    let server_id = field_or("server_id", "server_identity_hash")?;
    let tool_name = field_or("tool_name", "operation")?;
    let intent_text = field("intent", "")?;
    let operation = match call.get("operation") {
        Some(value) => py_str(value)?,
        None => tool_name.clone(),
    };
    let target_origin = field("target_origin", "")?;
    let target_path_prefix = field("target_path_prefix", "")?;
    let profile_mode = field("profile_mode", "")?;
    let schema_hash = field_or("schema_hash", "mcp_schema_hash")?;
    let flags = match call.get("sensitive_surface_flags") {
        Some(Value::Array(items)) => {
            let mut texts = Vec::with_capacity(items.len());
            for item in items {
                texts.push(py_str(item)?);
            }
            texts.sort();
            texts.join(",")
        }
        Some(value) if is_truthy(value) => py_str(value)?,
        _ => String::new(),
    };
    let source = format!(
        "{server_id}:{tool_name}:{intent_text}:{operation}:{target_origin}:{target_path_prefix}:{profile_mode}:{schema_hash}:{flags}"
    );
    Some(hex::encode(Sha256::digest(source.as_bytes())))
}

/// `_build_queue_group_id`.
fn build_queue_group_id(
    item: &ApprovalQueueIdentityItemV1,
    action_identity: &str,
) -> Option<String> {
    let browser = match &item.browser_intent {
        None | Some(Value::Null) => Value::Null,
        Some(intent) => Value::String(browser_identity_hash(intent)?),
    };
    let payload = json!({
        "version": IDENTITY_VERSION,
        "harness": item.harness,
        "workspace": item.workspace,
        "artifact_id": item.artifact_id,
        "action_identity": action_identity,
        "browser_identity_hash": browser,
    });
    let digest = hex::encode(Sha256::digest(dumps_sorted(&payload)?.as_bytes()));
    Some(format!("approval-group:{IDENTITY_VERSION}:{digest}"))
}

#[cfg(test)]
#[path = "approval_queue_identity_vectors_tests.rs"]
mod vectors;
