//! Read-only data diagnostic for a signed Python v1 model budget.
//! Caller-supplied pins are not independently attested by this binary.

use base64::{engine::general_purpose::STANDARD, Engine};
use gauntlet_contracts::canonicalize;
use gauntlet_evidence::verify_signed_model_budget;
use serde_json::{json, Value};
use std::io::{self, Read};

const MAX_REQUEST_BYTES: usize = 8 * 1024 * 1024 + 64 * 1024;

fn evaluate(raw: &[u8]) -> Result<Value, String> {
    if raw.len() > MAX_REQUEST_BYTES {
        return Err("shadow model-budget request exceeds byte budget".into());
    }
    let canonical = canonicalize(raw).map_err(|error| error.to_string())?;
    let input: Value = serde_json::from_slice(&canonical).map_err(|error| error.to_string())?;
    let input = input
        .as_object()
        .ok_or("shadow model-budget request must be an object")?;
    const FIELDS: [&str; 9] = [
        "schema",
        "model_budget",
        "producer_public_key",
        "model_id",
        "max_tokens",
        "config_digest",
        "maximum_requests",
        "expected_sources",
        "base_url",
    ];
    if input.len() != FIELDS.len()
        || FIELDS.iter().any(|field| !input.contains_key(*field))
        || input.get("schema").and_then(Value::as_str)
            != Some("hol-gauntlet-model-budget-shadow-request.v1")
    {
        return Err("invalid shadow model-budget request fields".into());
    }
    let key = input
        .get("producer_public_key")
        .and_then(Value::as_str)
        .ok_or("missing model-budget public key")?;
    let key = STANDARD.decode(key).map_err(|error| error.to_string())?;
    let model_id = input
        .get("model_id")
        .and_then(Value::as_str)
        .ok_or("missing model identifier")?;
    let max_tokens = input
        .get("max_tokens")
        .and_then(Value::as_u64)
        .ok_or("invalid model token threshold")?;
    let maximum_requests = input
        .get("maximum_requests")
        .and_then(Value::as_u64)
        .ok_or("invalid maximum model requests")?;
    let config_digest = input.get("config_digest").ok_or("missing config digest")?;
    let config_digest = if config_digest.is_null() {
        None
    } else {
        Some(config_digest.as_str().ok_or("invalid config digest")?)
    };
    let base_url = input
        .get("base_url")
        .and_then(Value::as_str)
        .ok_or("missing model base URL")?;
    let sources = input
        .get("expected_sources")
        .ok_or("missing outside source pins")?;
    let envelope = serde_json::to_vec(input.get("model_budget").ok_or("missing model budget")?)
        .map_err(|error| error.to_string())?;
    let usage = verify_signed_model_budget(
        &envelope,
        &key,
        model_id,
        max_tokens,
        config_digest,
        Some(maximum_requests),
        sources,
        base_url,
    )
    .map_err(|error| error.to_string())?;
    Ok(json!({
        "schema":"hol-gauntlet-model-budget-shadow-response.v1",
        "status":"observed",
        "usage":usage,
        "execution_eligible":false,
    }))
}

fn main() {
    let mut raw = Vec::new();
    let result = io::stdin()
        .take((MAX_REQUEST_BYTES + 1) as u64)
        .read_to_end(&mut raw)
        .map_err(|error| error.to_string())
        .and_then(|_| evaluate(&raw));
    match result {
        Ok(value) => println!("{value}"),
        Err(error) => {
            println!(
                "{}",
                json!({
                    "schema":"hol-gauntlet-model-budget-shadow-response.v1",
                    "status":"invalid",
                    "reason":error,
                    "execution_eligible":false,
                })
            );
            std::process::exit(2);
        }
    }
}
