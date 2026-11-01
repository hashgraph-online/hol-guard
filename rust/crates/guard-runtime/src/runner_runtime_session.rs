//! The Guard Cloud runtime-session payload, for `RunnerAuthority`.
//!
//! Python hands over the local session record with the device identity, the
//! working directory, the clock and the client version. The answer is the
//! session the Cloud handshake sends, without the fields Python still reads
//! from the store (local identity, package-manager coverage and the managed
//! controls posture), which it adds afterwards.

use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use super::cloud_request_text::{py_strip, py_truthy};
use super::runner_authority_detector::args_object;
use super::runner_authority_op::{KindResult, ERR_INVALID};

/// Hex characters of the derived session id.
const DERIVED_SESSION_ID_CHARS: usize = 24;

pub(crate) fn runtime_session_payload(args: &Value) -> KindResult {
    let args = args_object(args)?;
    let Some(Value::Object(session)) = args.get("session") else {
        return Err(ERR_INVALID);
    };
    let text = |key: &str| args.get(key).and_then(Value::as_str).ok_or(ERR_INVALID);
    let device_id = text("device_id")?;
    let device_name = text("device_name")?;
    let cwd = text("cwd")?;
    let now = text("now")?;
    let version = text("version")?;

    let field = |snake: &str, camel: &str| non_blank(either(session, snake, camel));
    let own = |key: &str| non_blank(session.get(key));
    let workspace = own("workspace").unwrap_or(cwd);
    let session_id = field("session_id", "sessionId").map_or_else(
        || {
            let digest = hex::encode(Sha256::digest(format!("{device_id}:{workspace}")));
            digest[..DERIVED_SESSION_ID_CHARS].to_owned()
        },
        str::to_owned,
    );
    let created_at = field("created_at", "createdAt").unwrap_or(now);
    let updated_at = field("updated_at", "updatedAt").unwrap_or(created_at);

    let mut payload = Map::new();
    let mut put = |key: &str, value: Value| {
        payload.insert(key.to_owned(), value);
    };
    put("sessionId", json!(session_id));
    put("harness", json!(own("harness").unwrap_or("hol-guard")));
    put("surface", json!(own("surface").unwrap_or("cli")));
    put("status", json!(own("status").unwrap_or("active")));
    put(
        "clientName",
        json!(field("client_name", "clientName").unwrap_or("hol-guard")),
    );
    put(
        "clientTitle",
        json!(field("client_title", "clientTitle")
            .map_or_else(|| format!("HOL Guard on {device_name}"), str::to_owned)),
    );
    put(
        "clientVersion",
        json!(field("client_version", "clientVersion").unwrap_or(version)),
    );
    put("deviceId", json!(device_id));
    put("deviceName", json!(device_name));
    put("workspace", json!(workspace));
    put(
        "capabilities",
        Value::Array(string_items(session.get("capabilities"))),
    );
    put("operations", json!([]));
    put("createdAt", json!(created_at));
    put("updatedAt", json!(updated_at));
    for (snake, camel) in [
        ("policy_document_versions", "policyDocumentVersions"),
        ("policy_bundle_versions", "policyBundleVersions"),
        ("policy_contracts", "policyContracts"),
    ] {
        let items = string_items(either(session, snake, camel));
        if !items.is_empty() {
            put(camel, Value::Array(items));
        }
    }
    let flag = |snake: &str, camel: &str| {
        session.get(snake) == Some(&Value::Bool(true))
            || session.get(camel) == Some(&Value::Bool(true))
    };
    put("yamlImport", json!(flag("yaml_import", "yamlImport")));
    if flag("canonical_policy_enforcement", "canonicalPolicyEnforcement") {
        put("canonicalPolicyEnforcement", json!(true));
    }
    Ok(Value::Object(payload))
}

/// `session.get(snake) or session.get(camel)`: the first truthy value.
fn either<'a>(session: &'a Map<String, Value>, snake: &str, camel: &str) -> Option<&'a Value> {
    match session.get(snake) {
        Some(value) if py_truthy(value) => Some(value),
        _ => session.get(camel),
    }
}

/// `_optional_string`: a string with a non-blank character, kept as written.
fn non_blank(value: Option<&Value>) -> Option<&str> {
    value
        .and_then(Value::as_str)
        .filter(|text| !py_strip(text).is_empty())
}

/// `_string_items`: the string members of a list, anything else as none.
fn string_items(value: Option<&Value>) -> Vec<Value> {
    match value {
        Some(Value::Array(items)) => items
            .iter()
            .filter(|item| item.is_string())
            .cloned()
            .collect(),
        _ => Vec::new(),
    }
}
