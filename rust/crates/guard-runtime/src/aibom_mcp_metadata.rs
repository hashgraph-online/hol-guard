//! `enrich_mcp_server_metadata`: the configured-value digests and the content
//! hash that bind an MCP server definition for approval drift detection.

use std::collections::BTreeMap;

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::aibom_artifact::content_version_info;
use super::context_digest::{
    configured_values_hash, python_strip, CONFIGURED_ENV_HASH_DOMAIN, CONFIGURED_HEADER_HASH_DOMAIN,
};

pub(crate) const ERR_METADATA: &str = "native_runner_authority_aibom_mcp_metadata_invalid";

pub(crate) struct McpMetadataInput {
    pub(crate) command: Option<String>,
    pub(crate) args: Vec<String>,
    pub(crate) url: Option<String>,
    pub(crate) transport: Option<String>,
    pub(crate) env_keys: Vec<String>,
    pub(crate) headers_keys: Vec<String>,
    pub(crate) env: Value,
    pub(crate) headers: Value,
    pub(crate) env_values_hash: Option<String>,
    pub(crate) header_values_hash: Option<String>,
    pub(crate) label: String,
}

fn canonical_keys(items: &[String]) -> Vec<String> {
    let mut keys: Vec<String> = items
        .iter()
        .map(|item| python_strip(item).to_owned())
        .filter(|item| !item.is_empty())
        .collect();
    keys.sort();
    keys.dedup();
    keys
}

/// Ordered `[key, value]` pairs keep the last of any keys that collide after
/// stripping; only string keys and string values survive.
fn canonical_values(pairs: &Value) -> BTreeMap<String, String> {
    let mut values = BTreeMap::new();
    for pair in pairs.as_array().map(Vec::as_slice).unwrap_or_default() {
        let Some([key, value]) = pair.as_array().map(Vec::as_slice) else {
            continue;
        };
        let (Some(key), Some(value)) = (key.as_str(), value.as_str()) else {
            continue;
        };
        let key = python_strip(key);
        if !key.is_empty() {
            values.insert(key.to_owned(), value.to_owned());
        }
    }
    values
}

fn explicit_hash(raw: &Option<String>) -> Option<String> {
    raw.as_deref()
        .map(python_strip)
        .filter(|text| !text.is_empty())
        .map(str::to_owned)
}

fn values_digest(
    keys: &[String],
    values: &BTreeMap<String, String>,
    explicit: &Option<String>,
    domain: &[u8],
) -> Result<String, &'static str> {
    if let Some(hash) = explicit_hash(explicit) {
        return Ok(hash);
    }
    let pairs = Value::Array(
        values
            .iter()
            .map(|(key, value)| json!([key, value]))
            .collect(),
    );
    configured_values_hash(Some(&pairs), Some(keys), domain)
}

fn resolved_keys(raw: &[String], values: &BTreeMap<String, String>) -> Vec<String> {
    let keys = canonical_keys(raw);
    if keys.is_empty() && !values.is_empty() {
        return values.keys().cloned().collect();
    }
    keys
}

pub(crate) fn enrich(input: &McpMetadataInput) -> Result<Value, &'static str> {
    let env = canonical_values(&input.env);
    let env_keys = resolved_keys(&input.env_keys, &env);
    let env_values_hash = values_digest(
        &env_keys,
        &env,
        &input.env_values_hash,
        CONFIGURED_ENV_HASH_DOMAIN,
    )?;
    let headers = canonical_values(&input.headers);
    let headers_keys = resolved_keys(&input.headers_keys, &headers);
    let header_values_hash = values_digest(
        &headers_keys,
        &headers,
        &input.header_values_hash,
        CONFIGURED_HEADER_HASH_DOMAIN,
    )?;
    let material = json!({
        "command": input.command,
        "args": input.args,
        "url": input.url,
        "transport": input.transport,
        "env_keys": env_keys,
        "env_values_hash": env_values_hash,
        "headers_keys": headers_keys,
        "header_values_hash": header_values_hash,
    });
    let mut bytes = Vec::new();
    guard_contracts::write_canonical_json_with_limit(
        &material,
        &mut bytes,
        usize::MAX,
        ERR_METADATA,
    )?;
    let content_hash = hex::encode(Sha256::digest(&bytes));
    Ok(json!({
        "env_keys": env_keys,
        "headers_keys": headers_keys,
        "env_values_hash": env_values_hash,
        "header_values_hash": header_values_hash,
        "content_hash": content_hash,
        "versionInfo": content_version_info(&content_hash, &input.label),
    }))
}
