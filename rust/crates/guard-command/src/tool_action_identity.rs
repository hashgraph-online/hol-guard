//! Rust port of the sensitive tool-action request artifact identity
//! (`runtime/secret_file_request_services/benign_requests.py`
//! `build_tool_action_request_artifact` :120-165).
//!
//! The id this produces is the key a saved approval for a sensitive tool
//! action is stored under. Two implementations of it would silently re-key
//! reviews the user had already approved, so the fingerprint has exactly one
//! derivation and it lives here.
//!
//! The fingerprint material is the Python payload byte for byte: the same
//! keys, the same conditional presence for the three optional identities, and
//! `json.dumps(payload, sort_keys=True)` with the *default* separators
//! `(", ", ": ")` rather than the compact canonical codec. Shortening the
//! separators here would change every id.

use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::package_intent_common::write_spaced_sorted_json;

/// Everything the id is derived from. The values are the request's exact
/// ones, not their redacted spellings: the fingerprint has to keep
/// distinguishing two actions that redact to the same text.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ToolActionIdentityInputs {
    pub harness: String,
    pub source_scope: String,
    /// `request.normalized_tool_name`, which the payload spells `tool_name`.
    pub normalized_tool_name: String,
    pub command_text: String,
    pub action_class: String,
    pub shell_execution_context_hash: Option<String>,
    /// `ToolActionRequestMatch.interpreter_executable_identities`: already
    /// JSON objects on both sides, so they cross the wire unchanged.
    #[serde(default)]
    pub interpreter_executable_identities: Vec<Value>,
    pub script_read_identity_sha256: Option<String>,
    pub restricted_profile_version: Option<String>,
    pub pytest_config_identity_sha256: Option<String>,
}

/// The hex SHA-256 over the fingerprint payload (:120-134).
pub fn tool_action_request_fingerprint(inputs: &ToolActionIdentityInputs) -> String {
    let mut payload = Map::new();
    payload.insert("harness".to_owned(), json!(inputs.harness));
    payload.insert("tool_name".to_owned(), json!(inputs.normalized_tool_name));
    payload.insert("command_text".to_owned(), json!(inputs.command_text));
    payload.insert("action_class".to_owned(), json!(inputs.action_class));
    payload.insert(
        "shell_execution_context_hash".to_owned(),
        json!(inputs.shell_execution_context_hash),
    );
    payload.insert(
        "interpreter_executable_identities".to_owned(),
        Value::Array(inputs.interpreter_executable_identities.clone()),
    );
    // Python adds these three only when they are set, so a request without
    // them must not carry the key at all (:127-132).
    if let Some(value) = &inputs.script_read_identity_sha256 {
        payload.insert("script_read_identity_sha256".to_owned(), json!(value));
    }
    if let Some(value) = &inputs.restricted_profile_version {
        payload.insert("restricted_profile_version".to_owned(), json!(value));
    }
    if let Some(value) = &inputs.pytest_config_identity_sha256 {
        payload.insert("pytest_config_identity_sha256".to_owned(), json!(value));
    }
    let mut encoded = String::new();
    write_spaced_sorted_json(&Value::Object(payload), &mut encoded);
    hex::encode(Sha256::digest(encoded.as_bytes()))
}

/// `GuardArtifact.artifact_id` for a sensitive tool action (:163).
pub fn tool_action_request_artifact_id(inputs: &ToolActionIdentityInputs) -> String {
    format!(
        "{}:{}:tool-action:{}",
        inputs.harness,
        inputs.source_scope,
        tool_action_request_fingerprint(inputs)
    )
}
