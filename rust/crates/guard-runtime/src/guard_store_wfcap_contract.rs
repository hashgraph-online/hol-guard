//! Signed workflow-capability claim and receipt contracts: strict decoding
//! with the Python validation order and error codes, HMAC signing, and
//! verification. Contracts are held as canonical JSON values.

use serde_json::{Map, Value};

use crate::guard_store_wfcap_error::{cap, WfResult};
use crate::guard_store_wfcap_frame::{
    canonical, digest, digests_equal, frame, hmac_hex, ident, parse_ts, req_int, req_str,
    sha256_hex, strict, validate_key,
};

pub(crate) const CLAIM_SCHEMA: &str = "hol-guard.workflow-capability.v1";
pub(crate) const CLAIM_ENVELOPE_SCHEMA: &str = "hol-guard.workflow-capability-envelope.v1";
pub(crate) const RECEIPT_SCHEMA: &str = "hol-guard.workflow-capability-receipt.v1";
pub(crate) const RECEIPT_ENVELOPE_SCHEMA: &str =
    "hol-guard.workflow-capability-receipt-envelope.v1";
pub(crate) const ALGORITHM: &str = "hmac-sha256";

const BINDING_KEYS: [&str; 14] = [
    "operation_id",
    "resource_type",
    "resource_sha256",
    "repository_sha256",
    "workspace_sha256",
    "executable_sha256",
    "launch_sha256",
    "policy_id",
    "policy_version",
    "effect_id",
    "effect_version",
    "decision_id",
    "decision_version",
    "rules",
];
const BINDING_IDENTS: [&str; 8] = [
    "operation_id",
    "resource_type",
    "policy_id",
    "policy_version",
    "effect_id",
    "effect_version",
    "decision_id",
    "decision_version",
];
const BINDING_DIGESTS: [&str; 5] = [
    "resource_sha256",
    "repository_sha256",
    "workspace_sha256",
    "executable_sha256",
    "launch_sha256",
];
const CLAIM_KEYS: [&str; 13] = [
    "schema_version",
    "algorithm",
    "capability_id",
    "approval_provenance_id",
    "task_id",
    "nonce",
    "issuer_id",
    "subject_id",
    "binding",
    "issued_at",
    "not_before",
    "expires_at",
    "max_uses",
];
const RECEIPT_KEYS: [&str; 11] = [
    "schema_version",
    "receipt_id",
    "capability_id",
    "task_id",
    "invocation_id",
    "approval_provenance_id",
    "claim_sha256",
    "binding",
    "use_number",
    "event_id",
    "claimed_at",
];

pub(crate) fn text<'a>(value: &'a Value, name: &str) -> &'a str {
    value.get(name).and_then(Value::as_str).unwrap_or_default()
}

pub(crate) fn int(value: &Value, name: &str) -> i64 {
    value.get(name).and_then(Value::as_i64).unwrap_or_default()
}

fn validate_rule(value: &Value) -> WfResult<()> {
    let map = strict(value, &["rule_id", "rule_version"])?;
    let rule_id = req_str(map, "rule_id")?;
    let rule_version = req_str(map, "rule_version")?;
    ident("rule_id", &rule_id)?;
    ident("rule_version", &rule_version)
}

/// `WorkflowCapabilityBinding.from_dict` plus its `__post_init__`.
pub(crate) fn validate_binding(value: &Value) -> WfResult<()> {
    let map = strict(value, &BINDING_KEYS)?;
    let Some(rules) = map.get("rules").and_then(Value::as_array) else {
        return cap("invalid_rule_bindings");
    };
    for (name, item) in map {
        if name != "rules" && !item.is_string() {
            return cap(format!("invalid_{name}"));
        }
    }
    for rule in rules {
        validate_rule(rule)?;
    }
    for name in BINDING_IDENTS {
        ident(name, text(value, name))?;
    }
    for name in BINDING_DIGESTS {
        digest(name, text(value, name))?;
    }
    let mut keys: Vec<(&str, &str)> = rules
        .iter()
        .map(|rule| (text(rule, "rule_id"), text(rule, "rule_version")))
        .collect();
    let given = keys.clone();
    keys.sort_unstable();
    keys.dedup();
    if rules.is_empty() || rules.len() > 32 || given != keys {
        return cap("invalid_rule_bindings");
    }
    Ok(())
}

/// `WorkflowCapabilityClaim.from_dict` plus its `__post_init__`.
pub(crate) fn validate_claim(value: &Value) -> WfResult<()> {
    let map = strict(value, &CLAIM_KEYS)?;
    let max_uses = req_int(map, "max_uses", "invalid_capability_max_uses")?;
    for name in &CLAIM_KEYS[..8] {
        req_str(map, name)?;
    }
    validate_binding(&map["binding"])?;
    for name in &CLAIM_KEYS[9..12] {
        req_str(map, name)?;
    }
    if text(value, "schema_version") != CLAIM_SCHEMA {
        return cap("unsupported_capability_schema");
    }
    if text(value, "algorithm") != ALGORITHM {
        return cap("unsupported_capability_algorithm");
    }
    for name in [
        "capability_id",
        "approval_provenance_id",
        "task_id",
        "issuer_id",
        "subject_id",
    ] {
        ident(name, text(value, name))?;
    }
    let nonce = text(value, "nonce");
    let hex_nonce = (32..=64).contains(&nonce.len())
        && nonce
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
    if !hex_nonce {
        return cap("invalid_nonce");
    }
    let issued = parse_ts(text(value, "issued_at"))?;
    let not_before = parse_ts(text(value, "not_before"))?;
    let expires = parse_ts(text(value, "expires_at"))?;
    if !(issued <= not_before && not_before < expires) {
        return cap("invalid_capability_time_window");
    }
    if expires - issued > 86_400 * 1_000_000 {
        return cap("capability_ttl_exceeds_alpha_limit");
    }
    if !(1..=50).contains(&max_uses) {
        return cap("invalid_capability_max_uses");
    }
    Ok(())
}

fn envelope_strings(map: &Map<String, Value>) -> WfResult<()> {
    req_str(map, "envelope_schema")?;
    req_str(map, "algorithm")?;
    Ok(())
}

/// `SignedWorkflowCapability.from_dict` plus its `__post_init__`.
pub(crate) fn validate_signed_claim(value: &Value) -> WfResult<()> {
    let map = strict(
        value,
        &[
            "envelope_schema",
            "algorithm",
            "claim",
            "key_id",
            "signature",
        ],
    )?;
    envelope_strings(map)?;
    validate_claim(&map["claim"])?;
    req_str(map, "key_id")?;
    req_str(map, "signature")?;
    if text(value, "envelope_schema") != CLAIM_ENVELOPE_SCHEMA {
        return cap("unsupported_capability_envelope");
    }
    if text(value, "algorithm") != ALGORITHM
        || text(value, "algorithm") != text(&map["claim"], "algorithm")
    {
        return cap("unsupported_capability_algorithm");
    }
    ident("key_id", text(value, "key_id"))?;
    digest("signature", text(value, "signature"))
}

fn claim_signature(claim: &Value, key: &[u8], key_id: &str) -> WfResult<String> {
    validate_key(key)?;
    ident("key_id", key_id)?;
    validate_claim(claim)?;
    let authenticated = serde_json::json!({
        "algorithm": ALGORITHM,
        "claim": claim,
        "envelope_schema": CLAIM_ENVELOPE_SCHEMA,
        "key_id": key_id,
    });
    Ok(hmac_hex(key, &frame("claim-envelope", &authenticated)))
}

/// `sign_workflow_capability`: the signed envelope for a validated claim.
///
/// The resident owns the capability key, so no caller supplies a signature it
/// produced itself.
pub(crate) fn sign_claim(claim: &Value, key: &[u8], key_id: &str) -> WfResult<Value> {
    let signature = claim_signature(claim, key, key_id)?;
    Ok(serde_json::json!({
        "envelope_schema": CLAIM_ENVELOPE_SCHEMA,
        "algorithm": ALGORITHM,
        "claim": claim.clone(),
        "key_id": key_id,
        "signature": signature,
    }))
}

/// `verify_workflow_capability_signature` on a decoded envelope.
pub(crate) fn verify_claim_signature(signed: &Value, key: &[u8], key_id: &str) -> WfResult<()> {
    validate_key(key)?;
    let claim = &signed["claim"];
    if text(signed, "envelope_schema") != CLAIM_ENVELOPE_SCHEMA {
        return cap("unsupported_capability_envelope");
    }
    if text(claim, "schema_version") != CLAIM_SCHEMA {
        return cap("unsupported_capability_schema");
    }
    if text(signed, "algorithm") != ALGORITHM
        || text(claim, "algorithm") != text(signed, "algorithm")
    {
        return cap("unsupported_capability_algorithm");
    }
    ident("key_id", text(signed, "key_id"))?;
    digest("signature", text(signed, "signature"))?;
    if text(signed, "key_id") != key_id {
        return cap("capability_key_mismatch");
    }
    let expected = claim_signature(claim, key, key_id)?;
    if !digests_equal(&expected, text(signed, "signature")) {
        return cap("capability_signature_invalid");
    }
    Ok(())
}

/// `verify_workflow_capability`: signature, validity window and exact binding.
pub(crate) fn verify_claim(
    signed: &Value,
    key: &[u8],
    key_id: &str,
    now: &str,
    expected_binding: &Value,
) -> WfResult<()> {
    if validate_binding(expected_binding).is_err() {
        return cap("invalid_expected_capability_binding");
    }
    verify_claim_signature(signed, key, key_id)?;
    let current = parse_ts(now)?;
    let claim = &signed["claim"];
    if current < parse_ts(text(claim, "not_before"))? {
        return cap("capability_not_yet_valid");
    }
    if current >= parse_ts(text(claim, "expires_at"))? {
        return cap("capability_expired");
    }
    if &claim["binding"] != expected_binding {
        return cap("capability_context_mismatch");
    }
    Ok(())
}

/// `workflow_capability_claim_sha256`.
pub(crate) fn claim_sha256(signed: &Value) -> String {
    sha256_hex(&frame("signed-claim", signed))
}

/// `SignedWorkflowCapability` persisted form, decoded from stored text.
pub(crate) fn decode_signed_claim(encoded: &str) -> WfResult<Value> {
    let Ok(payload) = serde_json::from_str::<Value>(encoded) else {
        return cap("capability_payload_invalid");
    };
    validate_signed_claim(&payload)?;
    if canonical(&payload) != encoded {
        return cap("capability_payload_not_canonical");
    }
    Ok(payload)
}

/// `WorkflowCapabilityReceipt.from_dict` plus its `__post_init__`.
pub(crate) fn validate_receipt(value: &Value) -> WfResult<()> {
    let map = strict(value, &RECEIPT_KEYS)?;
    let use_number = req_int(map, "use_number", "invalid_receipt_use_number")?;
    let event_id = req_int(map, "event_id", "invalid_receipt_event_id")?;
    for name in &RECEIPT_KEYS[..7] {
        req_str(map, name)?;
    }
    validate_binding(&map["binding"])?;
    req_str(map, "claimed_at")?;
    if text(value, "schema_version") != RECEIPT_SCHEMA {
        return cap("unsupported_receipt_schema");
    }
    for name in [
        "receipt_id",
        "capability_id",
        "task_id",
        "invocation_id",
        "approval_provenance_id",
    ] {
        ident(name, text(value, name))?;
    }
    digest("claim_sha256", text(value, "claim_sha256"))?;
    parse_ts(text(value, "claimed_at"))?;
    if use_number < 1 {
        return cap("invalid_receipt_use_number");
    }
    if event_id < 1 {
        return cap("invalid_receipt_event_id");
    }
    Ok(())
}

/// `SignedWorkflowCapabilityReceipt.from_dict` plus its `__post_init__`.
pub(crate) fn validate_signed_receipt(value: &Value) -> WfResult<()> {
    let map = strict(
        value,
        &[
            "envelope_schema",
            "algorithm",
            "receipt",
            "key_id",
            "signature",
        ],
    )?;
    envelope_strings(map)?;
    validate_receipt(&map["receipt"])?;
    req_str(map, "key_id")?;
    req_str(map, "signature")?;
    if text(value, "envelope_schema") != RECEIPT_ENVELOPE_SCHEMA {
        return cap("unsupported_receipt_envelope");
    }
    if text(value, "algorithm") != ALGORITHM {
        return cap("unsupported_receipt_algorithm");
    }
    ident("key_id", text(value, "key_id"))?;
    digest("signature", text(value, "signature"))
}

fn receipt_signature(receipt: &Value, key: &[u8], key_id: &str) -> WfResult<String> {
    validate_key(key)?;
    ident("key_id", key_id)?;
    validate_receipt(receipt)?;
    let authenticated = serde_json::json!({
        "algorithm": ALGORITHM,
        "envelope_schema": RECEIPT_ENVELOPE_SCHEMA,
        "key_id": key_id,
        "receipt": receipt,
    });
    Ok(hmac_hex(key, &frame("receipt-envelope", &authenticated)))
}

/// `sign_workflow_capability_receipt`.
pub(crate) fn sign_receipt(receipt: &Value, key: &[u8], key_id: &str) -> WfResult<Value> {
    let signature = receipt_signature(receipt, key, key_id)?;
    Ok(serde_json::json!({
        "algorithm": ALGORITHM,
        "envelope_schema": RECEIPT_ENVELOPE_SCHEMA,
        "key_id": key_id,
        "receipt": receipt,
        "signature": signature,
    }))
}

/// `verify_workflow_capability_receipt` on a decoded envelope.
pub(crate) fn verify_receipt(signed: &Value, key: &[u8], key_id: &str) -> WfResult<()> {
    validate_key(key)?;
    let receipt = &signed["receipt"];
    if text(signed, "envelope_schema") != RECEIPT_ENVELOPE_SCHEMA {
        return cap("unsupported_receipt_envelope");
    }
    if text(receipt, "schema_version") != RECEIPT_SCHEMA {
        return cap("unsupported_receipt_schema");
    }
    if text(signed, "algorithm") != ALGORITHM {
        return cap("unsupported_receipt_algorithm");
    }
    ident("key_id", text(signed, "key_id"))?;
    digest("signature", text(signed, "signature"))?;
    if text(signed, "key_id") != key_id {
        return cap("receipt_key_mismatch");
    }
    let expected = receipt_signature(receipt, key, key_id)?;
    if !digests_equal(&expected, text(signed, "signature")) {
        return cap("receipt_signature_invalid");
    }
    Ok(())
}

/// `_decode_signed_receipt`.
pub(crate) fn decode_signed_receipt(encoded: &str) -> WfResult<Value> {
    let Ok(payload) = serde_json::from_str::<Value>(encoded) else {
        return cap("receipt_payload_invalid");
    };
    validate_signed_receipt(&payload)?;
    if canonical(&payload) != encoded {
        return cap("receipt_payload_not_canonical");
    }
    Ok(payload)
}
