//! `native_decision_receipt.py` — the strict privacy and idempotency check the
//! journal and the writer run over a receipt the decision edge emitted.
//!
//! The edge builds the receipt and derives `decision_id` from the identity
//! subset; this module is the consumer half that refuses anything it did not
//! build, so a journal line, a store row or a drained response that was edited
//! on disk never reaches a reader as evidence. It recomputes the same identity
//! digest rather than trusting the id that arrived.
//!
//! One deliberate tightening: Python compares `version` with `!=`, so a
//! receipt carrying `1.0` or `true` reaches its digest check, which then
//! rejects it only because the encoding differs. The validator refuses a
//! non-integer version outright. Every receipt the edge emits carries the
//! integer, so the answer for a real receipt is unchanged.

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::native_command_extension_evidence::valid_native_command_receipt_binding;

use super::ReceiptValidationApi;

/// `NATIVE_HOOK_DECISION_RECEIPT_SCHEMA`.
const RECEIPT_SCHEMA: &str = "guard-native-hook-decision-receipt.v1";
/// `NATIVE_HOOK_DECISION_RECEIPT_MAX_BYTES`.
const RECEIPT_MAX_BYTES: usize = 16 * 1024;
/// `NATIVE_HOOK_DECISION_RECEIPT_MAX_STRING_BYTES`.
const RECEIPT_MAX_STRING_BYTES: usize = 512;

const ACTIONS: [&str; 6] = [
    "allow",
    "warn",
    "review",
    "require-reapproval",
    "sandbox-required",
    "block",
];
const MODEL_ACTIONS: [&str; 4] = [
    "allow_original",
    "replace_with_reviewed_excerpt",
    "block",
    "not_applicable",
];
const PAYLOAD_KINDS: [&str; 3] = ["inline", "source_file_ref", "encrypted_payload_ref"];
const EVENT_NAMES: [&str; 3] = ["PreToolUse", "PostToolUse", "UserPromptSubmit"];
/// `_PROMPT_RISK_CLASSES` — the catalogue order a receipt must list in.
const PROMPT_RISK_CLASSES: [&str; 7] = [
    "local_env_read",
    "sensitive_material",
    "exfil_intent",
    "destructive_intent",
    "subprocess_intent",
    "guard_bypass_intent",
    "prompt_injection_intent",
];
const OPTIONAL_FIELDS: [&str; 6] = [
    "command_extensions",
    "origin_authentication",
    "execution_intent_digest",
    "review_anchor_digest",
    "prompt_risk_classes",
    "business_review_binding",
];
const REQUIRED_FIELDS: [&str; 23] = [
    "schema",
    "version",
    "authority",
    "decision_id",
    "request_id",
    "request_digest",
    "harness",
    "event_name",
    "payload_kind",
    "policy_generation",
    "policy_digest",
    "rule_digest",
    "runtime_identity",
    "decision",
    "model_output_action",
    "policy_action",
    "observed_policy_action",
    "reason_code",
    "workspace_bound",
    "source_ref_external_allowed",
    "reviewed_output_sha256",
    "observe_mode",
    "deadline_budget_ms",
];
/// The identity fields `_identity_payload` copies, in any order: the digest
/// writer sorts them.
const IDENTITY_FIELDS: [&str; 19] = [
    "request_id",
    "request_digest",
    "harness",
    "event_name",
    "payload_kind",
    "policy_generation",
    "policy_digest",
    "rule_digest",
    "runtime_identity",
    "decision",
    "model_output_action",
    "policy_action",
    "observed_policy_action",
    "reason_code",
    "workspace_bound",
    "source_ref_external_allowed",
    "reviewed_output_sha256",
    "observe_mode",
    "deadline_budget_ms",
];
/// The optional fields that join the identity when the receipt carries them.
const IDENTITY_OPTIONAL_FIELDS: [&str; 3] = [
    "command_extensions",
    "prompt_risk_classes",
    "business_review_binding",
];

/// The seam implementation the writer and the journal share.
pub struct NativeReceiptValidation;

impl ReceiptValidationApi for NativeReceiptValidation {
    fn validate_native_decision_receipt(
        &self,
        value: &Map<String, Value>,
    ) -> Option<Map<String, Value>> {
        validate_native_decision_receipt(value)
    }
}

/// `validate_native_decision_receipt(value)` — validate and copy one receipt
/// without retaining request material.
pub fn validate_native_decision_receipt(value: &Map<String, Value>) -> Option<Map<String, Value>> {
    if REQUIRED_FIELDS
        .iter()
        .any(|field| !value.contains_key(*field))
    {
        return None;
    }
    if value.keys().any(|field| {
        !REQUIRED_FIELDS.contains(&field.as_str()) && !OPTIONAL_FIELDS.contains(&field.as_str())
    }) {
        return None;
    }
    if let Some(extensions) = value.get("command_extensions") {
        if !valid_native_command_receipt_binding(extensions) {
            return None;
        }
    }
    let decision_id = validate_identity(value)?;
    if !validate_policy(value) || !validate_limits(value) {
        return None;
    }
    if decision_id != expected_decision_id(value)? {
        return None;
    }
    Some(value.clone())
}

/// `canonical_receipt_bytes` — the deterministic identity encoding shared with
/// the Rust edge (`sort_keys`, compact separators, UTF-8, no NaN).
pub fn canonical_receipt_bytes(receipt: &Map<String, Value>) -> Option<Vec<u8>> {
    let mut identity = Map::new();
    identity.insert(
        "schema".to_owned(),
        Value::String("guard-native-hook-decision-identity.v1".to_owned()),
    );
    identity.insert("version".to_owned(), Value::from(1));
    for field in IDENTITY_FIELDS
        .iter()
        .chain(IDENTITY_OPTIONAL_FIELDS.iter())
    {
        if let Some(carried) = receipt.get(*field) {
            identity.insert((*field).to_owned(), carried.clone());
        }
    }
    let mut out = Vec::new();
    guard_contracts::write_canonical_json_utf8(&Value::Object(identity), &mut out).ok()?;
    Some(out)
}

fn expected_decision_id(receipt: &Map<String, Value>) -> Option<String> {
    Some(hex::encode(Sha256::digest(canonical_receipt_bytes(
        receipt,
    )?)))
}

/// `_validate_receipt_identity` — the schema, the bounded identifiers and the
/// event/payload pairing. Returns the receipt's own `decision_id`.
fn validate_identity(receipt: &Map<String, Value>) -> Option<&str> {
    if receipt.get("schema")?.as_str() != Some(RECEIPT_SCHEMA) {
        return None;
    }
    if receipt.get("version")?.as_u64() != Some(1) {
        return None;
    }
    if receipt.get("authority")?.as_str() != Some("rust") {
        return None;
    }
    let decision_id = bounded(receipt.get("decision_id"), is_hex64, 64)?;
    bounded(receipt.get("request_id"), is_request_id, 256)?;
    bounded(receipt.get("request_digest"), is_hex64, 64)?;
    bounded(receipt.get("harness"), is_harness, 64)?;
    let event_name = receipt.get("event_name")?.as_str()?;
    if !EVENT_NAMES.contains(&event_name) {
        return None;
    }
    let payload_kind = receipt.get("payload_kind")?.as_str()?;
    if !PAYLOAD_KINDS.contains(&payload_kind) {
        return None;
    }
    if event_name == "UserPromptSubmit" && payload_kind != "inline" {
        return None;
    }
    let generation = unsigned(receipt.get("policy_generation"))?;
    if generation == 0 || generation > i64::MAX as u64 {
        return None;
    }
    Some(decision_id)
}

/// `_validate_receipt_policy` — the digests, the verdict vocabulary and the
/// prompt-only fields.
fn validate_policy(receipt: &Map<String, Value>) -> bool {
    for field in [
        "policy_digest",
        "rule_digest",
        "runtime_identity",
        "reviewed_output_sha256",
    ] {
        if !optional_digest(receipt.get(field)) {
            return false;
        }
    }
    let Some(event_name) = receipt.get("event_name").and_then(Value::as_str) else {
        return false;
    };
    let Some(decision) = receipt.get("decision").and_then(Value::as_str) else {
        return false;
    };
    if decision != "allow" && decision != "deny" {
        return false;
    }
    let Some(model_output_action) = receipt.get("model_output_action").and_then(Value::as_str)
    else {
        return false;
    };
    if !MODEL_ACTIONS.contains(&model_output_action) {
        return false;
    }
    if event_name == "UserPromptSubmit" && model_output_action != "not_applicable" {
        return false;
    }
    if let Some(classes) = receipt.get("prompt_risk_classes") {
        if event_name != "UserPromptSubmit" || !valid_prompt_risk_classes(classes) {
            return false;
        }
    }
    for field in ["policy_action", "observed_policy_action"] {
        match receipt.get(field) {
            Some(Value::Null) | None => {}
            Some(Value::String(action)) if ACTIONS.contains(&action.as_str()) => {}
            _ => return false,
        }
    }
    if bounded(
        receipt.get("reason_code"),
        is_identifier,
        RECEIPT_MAX_STRING_BYTES,
    )
    .is_none()
    {
        return false;
    }
    for field in [
        "origin_authentication",
        "execution_intent_digest",
        "review_anchor_digest",
        "business_review_binding",
    ] {
        if let Some(digest) = receipt.get(field) {
            if !digest.as_str().is_some_and(is_hex64) {
                return false;
            }
        }
    }
    true
}

/// `_validate_receipt_limits` — the booleans, the deadline and the encoded
/// size CPython measures with `ensure_ascii`.
fn validate_limits(receipt: &Map<String, Value>) -> bool {
    for field in [
        "workspace_bound",
        "source_ref_external_allowed",
        "observe_mode",
    ] {
        if !matches!(receipt.get(field), Some(Value::Bool(_))) {
            return false;
        }
    }
    match receipt.get("deadline_budget_ms") {
        Some(Value::Null) | None => {}
        budget => match unsigned(budget) {
            Some(budget) if (1..=9_000).contains(&budget) => {}
            _ => return false,
        },
    }
    let mut encoded = Vec::new();
    if guard_contracts::write_canonical_json(&Value::Object(receipt.clone()), &mut encoded).is_err()
    {
        return false;
    }
    encoded.len() <= RECEIPT_MAX_BYTES
}

/// `valid_prompt_risk_classes` — a non-empty bounded list in catalogue order
/// with no repeats.
pub fn valid_prompt_risk_classes(value: &Value) -> bool {
    let Some(items) = value.as_array() else {
        return false;
    };
    if items.is_empty() || items.len() > 6 {
        return false;
    }
    let mut previous: Option<usize> = None;
    for item in items {
        let Some(index) = item
            .as_str()
            .and_then(|name| PROMPT_RISK_CLASSES.iter().position(|known| *known == name))
        else {
            return false;
        };
        if previous.is_some_and(|earlier| earlier >= index) {
            return false;
        }
        previous = Some(index);
    }
    true
}

/// `_bounded_identifier(value, pattern=, maximum=)`.
fn bounded(value: Option<&Value>, pattern: fn(&str) -> bool, maximum: usize) -> Option<&str> {
    let text = value?.as_str()?;
    if text.is_empty() || text.chars().count() > maximum || !pattern(text) {
        return None;
    }
    Some(text)
}

/// `_optional_digest(value) is not _INVALID`.
fn optional_digest(value: Option<&Value>) -> bool {
    match value {
        Some(Value::Null) | None => true,
        Some(Value::String(digest)) => is_hex64(digest),
        _ => false,
    }
}

/// A JSON integer that is not a Python `bool`.
fn unsigned(value: Option<&Value>) -> Option<u64> {
    match value? {
        Value::Number(number) => number.as_u64(),
        _ => None,
    }
}

/// `_HEX64`.
fn is_hex64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

/// `_IDENTIFIER` — `^[a-z0-9][a-z0-9_.:-]{0,127}$`.
fn is_identifier(value: &str) -> bool {
    patterned(value, 128, |byte| {
        byte.is_ascii_lowercase()
            || byte.is_ascii_digit()
            || matches!(byte, b'_' | b'.' | b':' | b'-')
    })
}

/// `_REQUEST_ID` — `^[a-z0-9][a-z0-9_.:-]{0,255}$`.
fn is_request_id(value: &str) -> bool {
    patterned(value, 256, |byte| {
        byte.is_ascii_lowercase()
            || byte.is_ascii_digit()
            || matches!(byte, b'_' | b'.' | b':' | b'-')
    })
}

/// `_HARNESS` — `^[a-z0-9][a-z0-9-]{0,63}$`.
fn is_harness(value: &str) -> bool {
    patterned(value, 64, |byte| {
        byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'
    })
}

/// A lowercase-alphanumeric first character followed by `tail` characters, up
/// to `maximum` in all.
fn patterned(value: &str, maximum: usize, tail: fn(u8) -> bool) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() > maximum || !value.is_ascii() {
        return false;
    }
    let Some(first) = bytes.first() else {
        return false;
    };
    if !first.is_ascii_lowercase() && !first.is_ascii_digit() {
        return false;
    }
    bytes[1..].iter().all(|byte| tail(*byte))
}

#[cfg(test)]
#[path = "hook_evidence_receipt_tests.rs"]
mod tests;
