//! `RetryLineageCapture` — resident op that captures a hook's provider retry
//! lineage.
//!
//! Python held the capture half of this grammar: which payload aliases name a
//! session, thread, tool call, turn, invocation, provider request, workspace
//! and device; when two aliases disagree; what a clean identifier is; and how
//! the workspace, device, action envelope and record are digested. The
//! validating half already lived in `guard_store_lineage`, which keeps the
//! first valid lineage on an operation, so both halves now share one
//! identifier rule and one record digest.
//!
//! The record is diagnostic correlation only. Nothing reads it as a
//! capability, and a payload the grammar refuses simply carries no lineage.

use guard_contracts::{
    RetryLineageCaptureRequestV1, RetryLineageCaptureResultV1,
    RETRY_LINEAGE_CAPTURE_MAX_REQUEST_BYTES, RETRY_LINEAGE_CAPTURE_REQUEST_SCHEMA,
    RETRY_LINEAGE_CAPTURE_RESULT_SCHEMA,
};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::guard_store_lineage::{digest, identifier};
use crate::package_authority_op::request_digest_with_limit;

const LINEAGE_VERSION: u64 = 1;
const PROVIDER_ALIASES: [(&str, &[&str]); 5] = [
    ("session_id", &["session_id", "sessionId"]),
    (
        "thread_id",
        &[
            "thread_id",
            "threadId",
            "conversation_id",
            "conversationId",
            "codex_thread_id",
        ],
    ),
    (
        "tool_call_id",
        &[
            "tool_call_id",
            "toolCallId",
            "tool_use_id",
            "toolUseId",
            "call_id",
            "callId",
        ],
    ),
    ("turn_id", &["turn_id", "turnId", "codex_turn_id"]),
    (
        "invocation_id",
        &["invocation_id", "invocationId", "event_id", "eventId"],
    ),
];
const PROVIDER_REQUEST_KEYS: &[&str] = &[
    "request_id",
    "requestId",
    "approval_request_id",
    "approvalRequestId",
];
const WORKSPACE_KEYS: &[&str] = &["workspace", "cwd", "working_directory", "workingDirectory"];
const DEVICE_KEYS: &[&str] = &[
    "device_id",
    "deviceId",
    "device_fingerprint",
    "deviceFingerprint",
];

/// The one identifier `keys` name in `payload`. `Err` when an alias holds a
/// malformed value or two aliases name different identifiers; a null member
/// counts as absent.
fn payload_identifier<'a>(
    payload: &'a Map<String, Value>,
    keys: &[&str],
) -> Result<Option<&'a str>, ()> {
    let mut found = None;
    for key in keys {
        let value = match payload.get(*key) {
            None | Some(Value::Null) => continue,
            Some(value) => value,
        };
        let text = identifier(value).ok_or(())?;
        if found.is_some_and(|previous| previous != text) {
            return Err(());
        }
        found = Some(text);
    }
    Ok(found)
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// The lineage record `request` describes, or `None` when the payload names
/// no provider identifier, or names an ambiguous or malformed one.
pub(crate) fn capture(request: &RetryLineageCaptureRequestV1) -> Option<Map<String, Value>> {
    let payload = &request.payload;
    let harness = identifier(&Value::String(request.harness.clone()))?.to_owned();
    let mut lineage = Map::new();
    lineage.insert("version".to_owned(), json!(LINEAGE_VERSION));
    lineage.insert("source".to_owned(), json!("hook"));
    lineage.insert("harness".to_owned(), json!(harness));
    let mut named = false;
    for (name, keys) in PROVIDER_ALIASES {
        if let Some(value) = payload_identifier(payload, keys).ok()? {
            lineage.insert(name.to_owned(), json!(value));
            named = true;
        }
    }
    if !named {
        return None;
    }
    if let Some(value) = payload_identifier(payload, PROVIDER_REQUEST_KEYS).ok()? {
        lineage.insert("provider_request_id".to_owned(), json!(value));
    }
    let payload_workspace = payload_identifier(payload, WORKSPACE_KEYS).ok()?;
    let workspace = match &request.workspace {
        Some(runtime) => {
            let runtime = Value::String(runtime.clone());
            let runtime = identifier(&runtime)?.to_owned();
            // Payload context is diagnostic only: it never overrides the
            // runtime workspace, and a contradictory claim refuses the record.
            if payload_workspace.is_some_and(|claimed| claimed != runtime) {
                return None;
            }
            Some(runtime)
        }
        None => payload_workspace.map(str::to_owned),
    };
    if let Some(workspace) = workspace {
        lineage.insert(
            "workspace_sha256".to_owned(),
            json!(sha256_hex(workspace.as_bytes())),
        );
    }
    if let Some(device) = payload_identifier(payload, DEVICE_KEYS).ok()? {
        lineage.insert(
            "device_sha256".to_owned(),
            json!(sha256_hex(device.as_bytes())),
        );
    }
    if let Some(envelope) = &request.action_envelope {
        let mut bytes = Vec::new();
        guard_contracts::write_canonical_json_utf8(&Value::Object(envelope.clone()), &mut bytes)
            .ok()?;
        lineage.insert("action_sha256".to_owned(), json!(sha256_hex(&bytes)));
    }
    let lineage_id = digest(&lineage);
    lineage.insert("lineage_id".to_owned(), json!(lineage_id));
    Some(lineage)
}

pub(crate) fn evaluate_retry_lineage_capture(
    request: &RetryLineageCaptureRequestV1,
) -> Result<Vec<u8>, String> {
    let request_sha256 =
        request_digest_with_limit(request, RETRY_LINEAGE_CAPTURE_MAX_REQUEST_BYTES)?;
    if request.schema != RETRY_LINEAGE_CAPTURE_REQUEST_SCHEMA {
        return Err("native_retry_lineage_capture_schema_mismatch".to_owned());
    }
    if request.request_id.is_empty() {
        return Err("native_retry_lineage_capture_invalid".to_owned());
    }
    crate::encode_response(&RetryLineageCaptureResultV1 {
        schema: RETRY_LINEAGE_CAPTURE_RESULT_SCHEMA.to_owned(),
        request_id: request.request_id.clone(),
        request_sha256,
        status: "ok".to_owned(),
        code: "ok".to_owned(),
        lineage: capture(request),
    })
}

#[cfg(test)]
#[path = "retry_lineage_capture_op_tests.rs"]
mod tests;
