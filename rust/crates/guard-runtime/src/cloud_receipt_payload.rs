//! Cloud receipt sync payload (`runner.py` `_cloud_sync_receipt_payload` and
//! its helpers): a stored receipt row becomes the Cloud-safe receipt the
//! portal ingests. Pure; the caller supplies device metadata and the clock.

use base64ct::{Base64UrlUnpadded, Encoding};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use super::cloud_request_text::{py_strip, py_truthy};
use super::cloud_sync_privacy::{command_display_part, sanitize_text, scrub_envelope_commands};
use super::runner_authority_detector::args_object;
use super::runner_authority_op::{KindResult, ERR_INVALID};

const REVIEW_TIER: [&str; 3] = ["review", "require-reapproval", "sandbox-required"];
const MAX_TARGETS: usize = 3;

/// `runner._optional_string`: the original (unstripped) non-blank string.
fn optional_string(value: Option<&Value>) -> Option<&str> {
    value
        .and_then(Value::as_str)
        .filter(|text| !py_strip(text).is_empty())
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// `_cloud_sync_receipt_fingerprint`.
fn receipt_fingerprint(receipt: &Map<String, Value>) -> Result<String, &'static str> {
    let mut encoded = Vec::new();
    guard_contracts::write_canonical_json(&Value::Object(receipt.clone()), &mut encoded)
        .map_err(|_| ERR_INVALID)?;
    Ok(sha256_hex(&encoded))
}

/// `_cloud_sync_artifact_type`.
fn artifact_type(artifact_id: &str) -> &'static str {
    if artifact_id.starts_with("skill:") || artifact_id.contains(":skill:") {
        "skill"
    } else {
        "plugin"
    }
}

fn dashed(value: &str) -> String {
    let mut out = String::new();
    let mut pending = false;
    for character in value.to_lowercase().chars() {
        if character.is_ascii_lowercase() || character.is_ascii_digit() {
            if pending && !out.is_empty() {
                out.push('-');
            }
            pending = false;
            out.push(character);
        } else {
            pending = true;
        }
    }
    out
}

/// `_cloud_sync_artifact_slug`.
fn artifact_slug(artifact_name: &str, artifact_id: &str) -> String {
    let base = [py_strip(artifact_name), py_strip(artifact_id)]
        .into_iter()
        .find(|text| !text.is_empty())
        .unwrap_or("artifact");
    let slug = dashed(base);
    if !slug.is_empty() {
        return slug;
    }
    let fallback = dashed(artifact_id);
    if fallback.is_empty() {
        "artifact".to_owned()
    } else {
        fallback
    }
}

/// `_cloud_sync_recommendation`.
fn recommendation(policy_decision: &str) -> &'static str {
    if policy_decision == "block" {
        "block"
    } else if REVIEW_TIER.contains(&policy_decision) {
        "review"
    } else {
        "monitor"
    }
}

/// `_cloud_sync_receipt_action_command`.
fn action_command(envelope: &Map<String, Value>, level: &str) -> Option<String> {
    let tool_name = optional_string(envelope.get("tool_name"));
    let sanitized_tool = tool_name.map(command_display_part).unwrap_or_default();
    if let Some(command) = optional_string(envelope.get("command")) {
        if command != "guard_commands_module" {
            if level == "full" {
                return (!sanitized_tool.is_empty()).then_some(sanitized_tool);
            }
            return Some(command_display_part(command));
        }
    }
    let targets = envelope.get("target_paths").and_then(Value::as_array)?;
    if sanitized_tool.is_empty() {
        return None;
    }
    let raw: Vec<&str> = targets
        .iter()
        .take(MAX_TARGETS)
        .filter_map(Value::as_str)
        .filter(|text| !py_strip(text).is_empty())
        .collect();
    if !raw.is_empty() && level == "full" {
        let placeholder = if raw.len() > 1 {
            "[targets withheld]"
        } else {
            "[target withheld]"
        };
        return Some(format!("{sanitized_tool} {placeholder}"));
    }
    let mut parts = vec![sanitized_tool];
    parts.extend(
        raw.iter()
            .map(|target| command_display_part(target))
            .filter(|target| !target.is_empty()),
    );
    Some(parts.join(" "))
}

fn changed_since_last_approval(receipt: &Map<String, Value>, decision: &str) -> bool {
    if REVIEW_TIER.contains(&decision) {
        return true;
    }
    let explicit = match receipt.get("changedSinceLastApproval") {
        Some(Value::Bool(value)) => Some(*value),
        _ => match receipt.get("changed_since_last_approval") {
            Some(Value::Bool(value)) => Some(*value),
            _ => None,
        },
    };
    explicit == Some(true)
}

fn envelope_redacted(
    receipt: &Map<String, Value>,
    redacted: &Map<String, Value>,
    level: &str,
) -> Value {
    let mut enriched = scrub_envelope_commands(redacted, level);
    let Some(Value::Object(full)) = receipt.get("action_envelope_json") else {
        return Value::Object(enriched);
    };
    if let Some(command) = action_command(full, level) {
        enriched.remove("command");
        enriched.insert(
            "commandEncoded".to_owned(),
            Value::String(Base64UrlUnpadded::encode_string(command.as_bytes())),
        );
        enriched.insert(
            "commandTransport".to_owned(),
            Value::String("base64url-v1".to_owned()),
        );
    }
    if level == "none" {
        for key in ["target_paths", "network_hosts"] {
            if let Some(list @ Value::Array(_)) = full.get(key) {
                enriched.insert(key.to_owned(), list.clone());
            }
        }
        if let Some(Value::String(name)) = full.get("package_name").filter(|v| py_truthy(v)) {
            enriched.insert("package_name".to_owned(), Value::String(name.clone()));
        }
    }
    Value::Object(enriched)
}

/// `_cloud_sync_receipt_payload`.
fn receipt_payload(
    receipt: &Map<String, Value>,
    device_id: &str,
    device_name: &str,
    level: &str,
    now: &str,
) -> Result<Value, &'static str> {
    let fingerprint = receipt_fingerprint(receipt)?;
    let artifact_id = optional_string(receipt.get("artifact_id")).map_or_else(
        || format!("guard:local-receipt:{}", &fingerprint[..24]),
        str::to_owned,
    );
    let artifact_name = optional_string(receipt.get("artifact_name")).unwrap_or(&artifact_id);
    let decision = optional_string(receipt.get("policy_decision")).unwrap_or("review");
    let fallback_summary = format!("Guard recorded a {decision} decision.");
    let capabilities: Vec<String> = receipt
        .get("capabilities")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(|item| sanitize_text(item, "redacted-capability"))
                .collect()
        })
        .unwrap_or_default();
    let summary_input = optional_string(receipt.get("provenance_summary"))
        .or_else(|| optional_string(receipt.get("capabilities_summary")))
        .unwrap_or(&fallback_summary);
    let artifact_hash = optional_string(receipt.get("artifact_hash"))
        .map_or_else(|| sha256_hex(artifact_id.as_bytes()), str::to_owned);
    let mut payload = json!({
        "receiptId": optional_string(receipt.get("receipt_id"))
            .map_or_else(|| format!("guard-receipt-{fingerprint}"), str::to_owned),
        "artifactId": artifact_id,
        "artifactName": artifact_name,
        "artifactType": artifact_type(&artifact_id),
        "artifactSlug": artifact_slug(artifact_name, &artifact_id),
        "artifactHash": artifact_hash,
        "capabilities": capabilities,
        "capturedAt": optional_string(receipt.get("timestamp")).unwrap_or(now),
        "changedSinceLastApproval": changed_since_last_approval(receipt, decision),
        "deviceId": device_id,
        "deviceName": device_name,
        "harness": optional_string(receipt.get("harness")).unwrap_or("unknown"),
        "policyDecision": decision,
        "recommendation": recommendation(decision),
        "summary": sanitize_text(summary_input, &fallback_summary),
    });
    let object = payload.as_object_mut().ok_or(ERR_INVALID)?;
    if let Some(raw) = optional_string(receipt.get("raw_command_text")) {
        object.insert(
            "raw_command_text".to_owned(),
            json!(command_display_part(raw)),
        );
    }
    if let Some(publisher) = optional_string(receipt.get("publisher")) {
        object.insert("publisher".to_owned(), json!(publisher));
    }
    if let Some(Value::Object(redacted)) = receipt.get("envelope_redacted_json") {
        if !redacted.is_empty() {
            object.insert(
                "envelopeRedacted".to_owned(),
                envelope_redacted(receipt, redacted, level),
            );
        }
    }
    Ok(payload)
}

/// Kind `cloud_sync_receipt_payloads`.
pub(crate) fn cloud_sync_receipt_payloads(args: &Value) -> KindResult {
    let args = args_object(args)?;
    let text = |key: &str| args.get(key).and_then(Value::as_str).ok_or(ERR_INVALID);
    let (device_id, device_name) = (text("device_id")?, text("device_name")?);
    let (level, now) = (text("redaction_level")?, text("now")?);
    let receipts = args
        .get("receipts")
        .and_then(Value::as_array)
        .ok_or(ERR_INVALID)?;
    let mut payloads = Vec::with_capacity(receipts.len());
    for receipt in receipts {
        payloads.push(receipt_payload(
            args_object(receipt)?,
            device_id,
            device_name,
            level,
            now,
        )?);
    }
    Ok(json!({ "payloads": payloads }))
}
