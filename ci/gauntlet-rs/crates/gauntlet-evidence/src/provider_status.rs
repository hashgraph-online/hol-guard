//! Pure, read-only parity with Python `verify_provider_status`.
//!
//! The status is an operational provider witness, never permission to infer
//! or evidence of a Guard outcome. Caller pins must come from outside it.

use crate::crypto::is_sha256;
use crate::payload::exact_keys;
use crate::{EvidenceError, Result};
use serde_json::{json, Value};

fn invalid(message: &'static str) -> EvidenceError {
    EvidenceError::Invalid(message)
}

fn digest_pin<'a>(pins: &'a Value, name: &str) -> Result<&'a str> {
    pins[name]
        .as_str()
        .filter(|value| is_sha256(value))
        .ok_or(invalid("external provider identity digest required"))
}

fn integer_pin(pins: &Value, name: &str, maximum: u64) -> Result<u64> {
    pins[name]
        .as_u64()
        .filter(|value| (1..=maximum).contains(value))
        .ok_or(invalid("external provider budget required"))
}

/// Validate the Python v1 quota adapter and an idle, known-usage snapshot.
/// A valid result is still only operational accounting; it grants no model
/// admission and is not independently authenticated until its journal is read.
pub fn verify_provider_status(value: &Value, pins: &Value) -> Result<Value> {
    let allowance = pins.get("quota_allowance_digest").is_some();
    let keys = if allowance {
        vec![
            "profile",
            "quota_config_digest",
            "quota_allowance_digest",
            "model_identity_digest",
            "binding_sha256",
            "adapter_sha256",
            "server_sha256",
            "token_cap",
            "maximum_requests",
        ]
    } else {
        vec![
            "profile",
            "quota_config_digest",
            "model_identity_digest",
            "binding_sha256",
            "adapter_sha256",
            "server_sha256",
            "token_cap",
            "maximum_requests",
        ]
    };
    if !exact_keys(pins, &keys) || pins["profile"] != "owned-mlx-serial.v1" {
        return Err(invalid("exact external provider pins required"));
    }
    let server = digest_pin(pins, "server_sha256")?;
    let adapter = digest_pin(pins, "adapter_sha256")?;
    let config = digest_pin(pins, "quota_config_digest")?;
    let model = digest_pin(pins, "model_identity_digest")?;
    let binding = digest_pin(pins, "binding_sha256")?;
    let allowance_digest = if allowance {
        Some(digest_pin(pins, "quota_allowance_digest")?)
    } else {
        None
    };
    let token_cap = integer_pin(pins, "token_cap", 1_000_000_000)?;
    let maximum_requests = integer_pin(pins, "maximum_requests", 10_000)?;

    if !exact_keys(
        value,
        &["adapter", "binding_sha256", "qualification", "quota"],
    ) || value["qualification"] != false
        || value["binding_sha256"] != binding
    {
        return Err(invalid(
            "provider binding differs from externally pinned deployment",
        ));
    }
    let mut expected = json!({
        "schema":"gauntlet-mlx-quota-adapter.v1",
        "server_sha256":server,
        "adapter_sha256":adapter,
        "quota_config_digest":config,
        "producer_mode":"serial-original-tokenization-and-generation",
        "counting":"full prompt including cached input plus every producer-emitted response token",
        "batching":false,
        "draft":false,
        "qualification_eligible":false,
    });
    if let Some(digest) = allowance_digest {
        expected["quota_allowance_digest"] = json!(digest);
    }
    if value["adapter"] != expected {
        return Err(invalid(
            "provider adapter differs from frozen serial exact-token profile",
        ));
    }

    let quota = &value["quota"];
    let mut quota_keys = vec![
        "charged_tokens",
        "known_tokens",
        "reserved_tokens",
        "requests",
        "maximum_requests",
        "pending_requests",
        "remaining_tokens",
        "token_cap",
        "schema",
        "config_digest",
        "model_identity_digest",
        "halted",
        "journal_hash",
        "qualification_eligible",
    ];
    if allowance_digest.is_some() {
        quota_keys.push("allowance_digest");
    }
    if !exact_keys(quota, &quota_keys) {
        return Err(invalid(
            "provider budget has changed identity, uncertain usage or inconsistent counts",
        ));
    }
    let numbers = [
        "charged_tokens",
        "known_tokens",
        "reserved_tokens",
        "requests",
        "maximum_requests",
        "pending_requests",
        "remaining_tokens",
        "token_cap",
    ];
    if numbers.iter().any(|key| quota[*key].as_u64().is_none()) {
        return Err(invalid(
            "provider budget has changed identity, uncertain usage or inconsistent counts",
        ));
    }
    let charged = quota["charged_tokens"].as_u64().expect("checked integer");
    let requests = quota["requests"].as_u64().expect("checked integer");
    if quota["schema"] != "gauntlet-provider-quota-status.v1"
        || quota["config_digest"] != config
        || quota["model_identity_digest"] != model
        || allowance_digest.is_some_and(|digest| quota["allowance_digest"] != digest)
        || quota["token_cap"] != token_cap
        || quota["maximum_requests"] != maximum_requests
        || requests > maximum_requests
        || quota["qualification_eligible"] != false
        || !quota["journal_hash"].as_str().is_some_and(is_sha256)
        || quota["halted"] != false
        || quota["pending_requests"] != 0
        || quota["reserved_tokens"] != 0
        || quota["known_tokens"] != charged
        || token_cap.checked_sub(charged) != quota["remaining_tokens"].as_u64()
    {
        return Err(invalid(
            "provider budget has changed identity, uncertain usage or inconsistent counts",
        ));
    }
    Ok(quota.clone())
}

#[cfg(test)]
#[path = "provider_status_tests.rs"]
mod tests;
