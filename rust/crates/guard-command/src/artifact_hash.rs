//! The artifact hash that binds a persisted approval to the artifact it covers.
//!
//! `GuardStore` keys saved decisions by this digest, so the value computed here
//! has to equal the one `consumer.service.artifact_hash` computed for the same
//! artifact: a different spelling would silently invalidate every approval the
//! user has already granted. That constraint is why the shaping below follows
//! the Python source rather than a tidier equivalent — the codex short payload,
//! the raw metadata that overwrites the redacted copy, the `env_keys` mirror
//! and the volatile keys dropped only for a normalized prompt request.

use guard_contracts::write_python_default_json;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::artifact_hash_url::{parse_qsl, urlencode, urlsplit, urlunsplit};

/// Metadata that varies between two requests for the same prompt file.
const PROMPT_FILE_HASH_VOLATILE_METADATA_KEYS: [&str; 6] = [
    "prompt_display_text",
    "prompt_matched_text",
    "prompt_signals",
    "request_summary",
    "runtime_request_reason",
    "runtime_request_summary",
];
const SECRET_QUERY_TOKENS: [&str; 4] = ["key", "token", "auth", "secret"];
const SECRET_METADATA_TOKENS: [&str; 6] =
    ["key", "token", "auth", "secret", "password", "credential"];
const REDACTED: &str = "*****";

/// `artifact_hash(artifact)` over a `GuardArtifact` serialized as its fields.
#[must_use]
pub fn artifact_hash(artifact: &Map<String, Value>) -> String {
    let payload = hash_payload(artifact);
    let mut encoded = Vec::new();
    write_python_default_json(&payload, &mut encoded)
        .expect("artifact payloads are always encodable");
    hex::encode(Sha256::digest(&encoded))
}

fn text<'a>(artifact: &'a Map<String, Value>, field: &str) -> &'a str {
    artifact.get(field).and_then(Value::as_str).unwrap_or("")
}

fn metadata_of(artifact: &Map<String, Value>) -> Map<String, Value> {
    artifact
        .get("metadata")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default()
}

/// `_codex_hook_identity`: only a codex hook carries a stable identity.
fn codex_hook_identity(artifact: &Map<String, Value>) -> Option<String> {
    if text(artifact, "harness") != "codex" || text(artifact, "artifact_type") != "hook" {
        return None;
    }
    artifact
        .get("metadata")
        .and_then(Value::as_object)
        .and_then(|metadata| metadata.get("codex_hook_identity"))
        .and_then(Value::as_str)
        .filter(|identity| !identity.is_empty())
        .map(str::to_owned)
}

/// `_hash_payload`.
fn hash_payload(artifact: &Map<String, Value>) -> Value {
    if let Some(identity) = codex_hook_identity(artifact) {
        return json!({
            "schema": "codex-hook-artifact-hash-v1",
            "harness": text(artifact, "harness"),
            "artifact_type": text(artifact, "artifact_type"),
            "source_scope": text(artifact, "source_scope"),
            "codex_hook_identity": identity,
        });
    }

    let mut payload = to_dict(artifact);
    let mut metadata = metadata_of(artifact);
    let normalized_prompt = text(artifact, "artifact_type") == "prompt_request"
        && metadata
            .get("normalized_path")
            .is_some_and(Value::is_string);
    if normalized_prompt {
        let redacted = payload
            .get("metadata")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();
        let intent_hash = redacted
            .get("prompt_intent_hash")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|hash| !hash.is_empty())
            .map(str::to_owned);
        metadata = redacted
            .into_iter()
            .filter(|(key, _)| !PROMPT_FILE_HASH_VOLATILE_METADATA_KEYS.contains(&key.as_str()))
            .collect();
        if let Some(hash) = intent_hash {
            metadata.insert("prompt_intent_hash".to_owned(), Value::String(hash));
        }
    }

    let env_keys = metadata
        .get("env_keys")
        .cloned()
        .unwrap_or_else(|| Value::Array(Vec::new()));
    payload.insert("metadata".to_owned(), Value::Object(metadata));
    payload.insert("env_keys".to_owned(), env_keys);
    Value::Object(payload)
}

/// `GuardArtifact.to_dict()`: every field but the runtime-private one, with
/// arguments, url and metadata redacted.
fn to_dict(artifact: &Map<String, Value>) -> Map<String, Value> {
    let mut payload = Map::new();
    for field in [
        "artifact_id",
        "name",
        "harness",
        "artifact_type",
        "source_scope",
        "config_path",
    ] {
        payload.insert(field.to_owned(), json!(text(artifact, field)));
    }
    for field in ["command", "transport", "publisher"] {
        let value = artifact.get(field).cloned().unwrap_or(Value::Null);
        payload.insert(field.to_owned(), value);
    }

    let args = artifact
        .get("args")
        .and_then(Value::as_array)
        .map(|args| {
            args.iter()
                .map(|value| match value.as_str() {
                    Some(text) => Value::String(redact_arg(text)),
                    None => value.clone(),
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    payload.insert("args".to_owned(), Value::Array(args));

    let url = match artifact.get("url").and_then(Value::as_str) {
        Some(url) => Value::String(redact_url(url)),
        None => Value::Null,
    };
    payload.insert("url".to_owned(), url);

    let metadata = redact_metadata(&Value::Object(metadata_of(artifact)), None);
    payload.insert("metadata".to_owned(), metadata);
    payload
}

/// `_redact_url`: mask secret-looking query parameters, re-encoding the query.
fn redact_url(value: &str) -> String {
    let Some(split) = urlsplit(value) else {
        return value.to_owned();
    };
    if split.query.is_empty() {
        return value.to_owned();
    }
    let redacted = parse_qsl(&split.query)
        .into_iter()
        .map(|(key, item)| {
            let lowered = key.to_lowercase();
            if SECRET_QUERY_TOKENS
                .iter()
                .any(|token| lowered.contains(token))
            {
                (key, REDACTED.to_owned())
            } else {
                (key, item)
            }
        })
        .collect::<Vec<_>>();
    urlunsplit(&split, &urlencode(&redacted))
}

/// `_redact_arg`: mask an inline header or query-style credential.
fn redact_arg(value: &str) -> String {
    let lowered = value.to_lowercase();
    if lowered.contains("authorization:")
        || lowered.contains("api-key:")
        || lowered.contains("bearer ")
    {
        let prefix = value.split_once(':').map_or(value, |(prefix, _)| prefix);
        return format!("{prefix}: {REDACTED}");
    }
    if ["apikey=", "api_key=", "api-key=", "token=", "secret="]
        .iter()
        .any(|token| lowered.contains(token))
    {
        let key = value.split_once('=').map_or(value, |(key, _)| key);
        return format!("{key}={REDACTED}");
    }
    value.to_owned()
}

/// `_redact_metadata`: mask environments and secret-keyed values recursively.
fn redact_metadata(value: &Value, key: Option<&str>) -> Value {
    if let Some(key) = key {
        let lowered = key.to_lowercase();
        if matches!(lowered.as_str(), "env" | "environment") {
            if let Some(entries) = value.as_object() {
                return Value::Object(
                    entries
                        .keys()
                        .map(|name| (name.clone(), Value::String(REDACTED.to_owned())))
                        .collect(),
                );
            }
        }
        if SECRET_METADATA_TOKENS
            .iter()
            .any(|token| lowered.contains(token))
        {
            return Value::String(REDACTED.to_owned());
        }
    }
    match value {
        Value::Object(entries) => Value::Object(
            entries
                .iter()
                .map(|(name, item)| (name.clone(), redact_metadata(item, Some(name))))
                .collect(),
        ),
        Value::Array(items) => Value::Array(
            items
                .iter()
                .map(|item| redact_metadata(item, None))
                .collect(),
        ),
        _ => value.clone(),
    }
}
