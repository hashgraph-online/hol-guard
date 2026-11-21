//! `workflow_capability_transitions.py` — the signed, append-only
//! authority-transition ledger contract (RTM-013 store substrate, pure half).
//!
//! `WorkflowCapabilityAuthorityTransition` links one authority-state revision
//! to the next: it pins the claim digest, the signed-state digest, the event
//! digest, and the previous-transition digest (`previous_transition_sha256`)
//! into an HMAC chain. `verify` recomputes the HMAC and compares in constant
//! time; `decode` enforces the exact key set and canonical encoding round-trip.
//!
//! The store half (`build_authority_transition` + `append_authority_transition`
//! + `validate_global_authority_ledger`) lives in `guard-runtime` atop
//!   `rusqlite`.

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::canonical_json::write_canonical_json;
use crate::workflow_capability::{
    canonical_framed_payload, validate_workflow_capability_identifier, WorkflowCapabilityError,
};

pub const AUTHORITY_TRANSITION_SCHEMA: &str =
    "hol-guard.workflow-capability-authority-transition.v1";
pub const AUTHORITY_TRANSITION_ALGORITHM: &str = "hmac-sha256";
pub const ZERO_TRANSITION_SHA256: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

type HmacSha256 = Hmac<Sha256>;
type WfResult<T> = Result<T, WorkflowCapabilityError>;
fn err<T>(reason: &'static str) -> WfResult<T> {
    Err(WorkflowCapabilityError(reason))
}

fn is_sha256(v: &str) -> bool {
    v.len() == 64
        && v.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// `_KINDS` — the three terminal transition kinds.
const KINDS: [&str; 3] = ["issued", "claimed", "revoked"];

/// `WorkflowCapabilityAuthorityTransition` — one immutable hash-chain link.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WorkflowCapabilityAuthorityTransition {
    pub schema_version: String,
    pub algorithm: String,
    pub sequence: i64,
    pub capability_id: String,
    pub claim_sha256: String,
    pub revision: i64,
    pub transition_kind: String,
    pub previous_transition_sha256: String,
    pub signed_state_sha256: String,
    pub event_id: Option<i64>,
    pub event_name: Option<String>,
    pub event_payload_sha256: Option<String>,
    pub occurred_at: String,
    pub use_number: Option<i64>,
    pub receipt_id: Option<String>,
    pub revocation_id: Option<String>,
}

impl WorkflowCapabilityAuthorityTransition {
    /// `__post_init__` — validate every field on construction.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sequence: i64,
        capability_id: impl Into<String>,
        claim_sha256: impl Into<String>,
        revision: i64,
        transition_kind: impl Into<String>,
        previous_transition_sha256: impl Into<String>,
        signed_state_sha256: impl Into<String>,
        event_id: Option<i64>,
        event_name: Option<String>,
        event_payload_sha256: Option<String>,
        occurred_at: impl Into<String>,
        use_number: Option<i64>,
        receipt_id: Option<String>,
        revocation_id: Option<String>,
    ) -> WfResult<Self> {
        let t = Self {
            schema_version: AUTHORITY_TRANSITION_SCHEMA.to_string(),
            algorithm: AUTHORITY_TRANSITION_ALGORITHM.to_string(),
            sequence,
            capability_id: capability_id.into(),
            claim_sha256: claim_sha256.into(),
            revision,
            transition_kind: transition_kind.into(),
            previous_transition_sha256: previous_transition_sha256.into(),
            signed_state_sha256: signed_state_sha256.into(),
            event_id,
            event_name,
            event_payload_sha256,
            occurred_at: occurred_at.into(),
            use_number,
            receipt_id,
            revocation_id,
        };
        t.validate()?;
        Ok(t)
    }

    fn validate(&self) -> WfResult<()> {
        if self.schema_version != AUTHORITY_TRANSITION_SCHEMA {
            return err("unsupported_authority_transition_schema");
        }
        if self.algorithm != AUTHORITY_TRANSITION_ALGORITHM {
            return err("unsupported_authority_transition_algorithm");
        }
        if self.sequence < 0 {
            return err("invalid_authority_transition_sequence");
        }
        validate_workflow_capability_identifier("capability_id", &self.capability_id)?;
        if !is_sha256(&self.claim_sha256) {
            return err("invalid_claim_sha256");
        }
        if self.revision < 0 {
            return err("invalid_revision");
        }
        if !KINDS.contains(&self.transition_kind.as_str()) {
            return err("invalid_transition_kind");
        }
        if !is_sha256(&self.previous_transition_sha256) {
            return err("invalid_previous_transition_sha256");
        }
        if !is_sha256(&self.signed_state_sha256) {
            return err("invalid_signed_state_sha256");
        }
        if let Some(n) = &self.event_name {
            if n.is_empty() {
                return err("invalid_event_name");
            }
        }
        if let Some(s) = &self.event_payload_sha256 {
            if !is_sha256(s) {
                return err("invalid_event_payload_sha256");
            }
        }
        if let Some(r) = &self.receipt_id {
            validate_workflow_capability_identifier("receipt_id", r)?;
        }
        if let Some(r) = &self.revocation_id {
            validate_workflow_capability_identifier("revocation_id", r)?;
        }
        Ok(())
    }

    /// `from_dict` — strict key set; every field typed.
    pub fn decode(payload: &Value) -> WfResult<Self> {
        let m = strict_object(
            payload,
            &[
                "schema_version",
                "algorithm",
                "sequence",
                "capability_id",
                "claim_sha256",
                "revision",
                "transition_kind",
                "previous_transition_sha256",
                "signed_state_sha256",
                "event_id",
                "event_name",
                "event_payload_sha256",
                "occurred_at",
                "use_number",
                "receipt_id",
                "revocation_id",
            ],
        )?;
        let t = Self {
            schema_version: string_field("schema_version", m)?,
            algorithm: string_field("algorithm", m)?,
            sequence: integer_field("sequence", m)?,
            capability_id: string_field("capability_id", m)?,
            claim_sha256: string_field("claim_sha256", m)?,
            revision: integer_field("revision", m)?,
            transition_kind: string_field("transition_kind", m)?,
            previous_transition_sha256: string_field("previous_transition_sha256", m)?,
            signed_state_sha256: string_field("signed_state_sha256", m)?,
            event_id: optional_integer_field("event_id", m)?,
            event_name: optional_string_field("event_name", m)?,
            event_payload_sha256: optional_string_field("event_payload_sha256", m)?,
            occurred_at: string_field("occurred_at", m)?,
            use_number: optional_integer_field("use_number", m)?,
            receipt_id: optional_string_field("receipt_id", m)?,
            revocation_id: optional_string_field("revocation_id", m)?,
        };
        t.validate()?;
        Ok(t)
    }

    /// `asdict` order → `to_value` for canonical framing.
    pub fn to_value(&self) -> Value {
        let mut m = Map::new();
        m.insert(
            "schema_version".into(),
            Value::String(self.schema_version.clone()),
        );
        m.insert("algorithm".into(), Value::String(self.algorithm.clone()));
        m.insert("sequence".into(), Value::from(self.sequence));
        m.insert(
            "capability_id".into(),
            Value::String(self.capability_id.clone()),
        );
        m.insert(
            "claim_sha256".into(),
            Value::String(self.claim_sha256.clone()),
        );
        m.insert("revision".into(), Value::from(self.revision));
        m.insert(
            "transition_kind".into(),
            Value::String(self.transition_kind.clone()),
        );
        m.insert(
            "previous_transition_sha256".into(),
            Value::String(self.previous_transition_sha256.clone()),
        );
        m.insert(
            "signed_state_sha256".into(),
            Value::String(self.signed_state_sha256.clone()),
        );
        m.insert(
            "event_id".into(),
            self.event_id.map(Value::from).unwrap_or(Value::Null),
        );
        m.insert(
            "event_name".into(),
            self.event_name
                .clone()
                .map(Value::String)
                .unwrap_or(Value::Null),
        );
        m.insert(
            "event_payload_sha256".into(),
            self.event_payload_sha256
                .clone()
                .map(Value::String)
                .unwrap_or(Value::Null),
        );
        m.insert(
            "occurred_at".into(),
            Value::String(self.occurred_at.clone()),
        );
        m.insert(
            "use_number".into(),
            self.use_number.map(Value::from).unwrap_or(Value::Null),
        );
        m.insert(
            "receipt_id".into(),
            self.receipt_id
                .clone()
                .map(Value::String)
                .unwrap_or(Value::Null),
        );
        m.insert(
            "revocation_id".into(),
            self.revocation_id
                .clone()
                .map(Value::String)
                .unwrap_or(Value::Null),
        );
        Value::Object(m)
    }
}

/// `SignedAuthorityTransition` — the transition plus its HMAC envelope.
#[derive(Debug, Clone, PartialEq)]
pub struct SignedAuthorityTransition {
    pub transition: WorkflowCapabilityAuthorityTransition,
    pub key_id: String,
    pub signature: String,
}

fn validate_key(key: &[u8]) -> WfResult<()> {
    if key.len() >= 32 {
        Ok(())
    } else {
        err("invalid_capability_key")
    }
}

/// `sign_authority_transition` — HMAC-SHA256 over the framed
/// `{key_id, transition}` envelope, purpose `authority-transition`.
pub fn sign_authority_transition(
    transition: WorkflowCapabilityAuthorityTransition,
    key: &[u8],
    key_id: &str,
) -> WfResult<SignedAuthorityTransition> {
    validate_key(key)?;
    validate_workflow_capability_identifier("key_id", key_id)?;
    let mut env = Map::new();
    env.insert("key_id".into(), Value::String(key_id.to_string()));
    env.insert("transition".into(), transition.to_value());
    let framed = canonical_framed_payload("authority-transition", &Value::Object(env))?;
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("hmac any len");
    mac.update(&framed);
    let signature = hex_lower(&mac.finalize().into_bytes());
    Ok(SignedAuthorityTransition {
        transition,
        key_id: key_id.to_string(),
        signature,
    })
}

/// `verify_authority_transition` — constant-time envelope check.
pub fn verify_authority_transition(
    signed: &SignedAuthorityTransition,
    key: &[u8],
    key_id: &str,
) -> WfResult<()> {
    if signed.key_id != key_id {
        return err("authority_transition_key_mismatch");
    }
    if !is_sha256(&signed.signature) {
        return err("invalid_signature");
    }
    let expected = sign_authority_transition(signed.transition.clone(), key, key_id)?.signature;
    if !constant_time_eq(expected.as_bytes(), signed.signature.as_bytes()) {
        return err("authority_transition_signature_invalid");
    }
    Ok(())
}

/// `encode_signed_authority_transition` — canonical JSON of the envelope.
pub fn encode_signed_authority_transition(signed: &SignedAuthorityTransition) -> WfResult<String> {
    let mut env = Map::new();
    env.insert("key_id".into(), Value::String(signed.key_id.clone()));
    env.insert("signature".into(), Value::String(signed.signature.clone()));
    env.insert("transition".into(), signed.transition.to_value());
    let mut buf = Vec::new();
    write_canonical_json(&Value::Object(env), &mut buf)
        .map_err(|_| WorkflowCapabilityError("invalid_canonical_payload"))?;
    String::from_utf8(buf).map_err(|_| WorkflowCapabilityError("invalid_canonical_payload"))
}

/// `decode_signed_authority_transition` — strict decode + canonical round-trip.
pub fn decode_signed_authority_transition(encoded: &str) -> WfResult<SignedAuthorityTransition> {
    let payload: Value = serde_json::from_str(encoded)
        .map_err(|_| WorkflowCapabilityError("authority_transition_payload_invalid"))?;
    let m = strict_object(&payload, &["key_id", "signature", "transition"])
        .map_err(|_| WorkflowCapabilityError("authority_transition_payload_invalid"))?;
    let transition = WorkflowCapabilityAuthorityTransition::decode(require(m, "transition")?)?;
    let signed = SignedAuthorityTransition {
        transition,
        key_id: require_str(m, "key_id")?,
        signature: require_str(m, "signature")?,
    };
    if encode_signed_authority_transition(&signed)? != encoded {
        return err("authority_transition_not_canonical");
    }
    Ok(signed)
}

/// `authority_transition_sha256` — sha256 of the framed encoded transition.
pub fn authority_transition_sha256(signed: &SignedAuthorityTransition) -> WfResult<String> {
    let encoded = encode_signed_authority_transition(signed)?;
    let framed = canonical_framed_payload("authority-transition-digest", &Value::String(encoded))?;
    Ok(hex_lower(&Sha256::digest(&framed)))
}

// ─── shared field codecs ─────────────────────────────────────────────────

fn strict_object<'v>(payload: &'v Value, expected: &[&str]) -> WfResult<&'v Map<String, Value>> {
    let m = payload
        .as_object()
        .ok_or(WorkflowCapabilityError("invalid_contract_keys"))?;
    if m.len() != expected.len() || !expected.iter().all(|k| m.contains_key(*k)) {
        return err("invalid_contract_keys");
    }
    Ok(m)
}

fn require<'v>(m: &'v Map<String, Value>, key: &str) -> WfResult<&'v Value> {
    m.get(key)
        .ok_or(WorkflowCapabilityError("invalid_contract_keys"))
}

fn require_str(m: &Map<String, Value>, key: &str) -> WfResult<String> {
    require(m, key)?
        .as_str()
        .map(str::to_string)
        .ok_or(WorkflowCapabilityError("invalid_field_type"))
}

fn string_field(name: &'static str, m: &Map<String, Value>) -> WfResult<String> {
    require(m, name)?
        .as_str()
        .map(str::to_string)
        .ok_or(WorkflowCapabilityError(name_err(name)))
}

fn optional_string_field(name: &'static str, m: &Map<String, Value>) -> WfResult<Option<String>> {
    match require(m, name)? {
        Value::Null => Ok(None),
        v => v
            .as_str()
            .map(|s| Some(s.to_string()))
            .ok_or(WorkflowCapabilityError(name_err(name))),
    }
}

fn integer_field(name: &'static str, m: &Map<String, Value>) -> WfResult<i64> {
    require(m, name)?
        .as_i64()
        .ok_or(WorkflowCapabilityError(name_err(name)))
}

fn optional_integer_field(name: &'static str, m: &Map<String, Value>) -> WfResult<Option<i64>> {
    match require(m, name)? {
        Value::Null => Ok(None),
        v => v
            .as_i64()
            .map(Some)
            .ok_or(WorkflowCapabilityError(name_err(name))),
    }
}

/// `_string`/`_integer`/`_optional_*` raise `WorkflowCapabilityError(f"invalid_{name}")`.
fn name_err(name: &'static str) -> &'static str {
    // The Python helper formats `invalid_{name}` dynamically; the fixed field
    // set means a static table keeps the messages verbatim.
    match name {
        "schema_version" => "invalid_schema_version",
        "algorithm" => "invalid_algorithm",
        "sequence" => "invalid_sequence",
        "capability_id" => "invalid_capability_id",
        "claim_sha256" => "invalid_claim_sha256",
        "revision" => "invalid_revision",
        "transition_kind" => "invalid_transition_kind",
        "previous_transition_sha256" => "invalid_previous_transition_sha256",
        "signed_state_sha256" => "invalid_signed_state_sha256",
        "event_id" => "invalid_event_id",
        "event_name" => "invalid_event_name",
        "event_payload_sha256" => "invalid_event_payload_sha256",
        "occurred_at" => "invalid_occurred_at",
        "use_number" => "invalid_use_number",
        "receipt_id" => "invalid_receipt_id",
        "revocation_id" => "invalid_revocation_id",
        "key_id" => "invalid_key_id",
        "signature" => "invalid_signature",
        _ => "invalid_field",
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> Vec<u8> {
        (0u8..64).collect()
    }
    const KEY_ID: &str = "key-1";

    fn transition() -> WorkflowCapabilityAuthorityTransition {
        WorkflowCapabilityAuthorityTransition::new(
            0,
            "cap-1",
            "a".repeat(64),
            0,
            "issued",
            ZERO_TRANSITION_SHA256,
            "b".repeat(64),
            Some(7),
            Some("workflow_capability.issued".to_string()),
            Some("c".repeat(64)),
            "2026-10-02T00:00:00.000000Z",
            None,
            None,
            None,
        )
        .unwrap()
    }

    #[test]
    fn sign_verify_round_trip() {
        let s = sign_authority_transition(transition(), &key(), KEY_ID).unwrap();
        verify_authority_transition(&s, &key(), KEY_ID).unwrap();
    }

    #[test]
    fn verify_rejects_wrong_key_and_tamper() {
        let s = sign_authority_transition(transition(), &key(), KEY_ID).unwrap();
        let bad_key = vec![9u8; 64];
        assert_eq!(
            verify_authority_transition(&s, &bad_key, KEY_ID).unwrap_err(),
            WorkflowCapabilityError("authority_transition_signature_invalid")
        );
        let mut tampered = s.clone();
        tampered.signature.replace_range(0..1, "f");
        assert_eq!(
            verify_authority_transition(&tampered, &key(), KEY_ID).unwrap_err(),
            WorkflowCapabilityError("authority_transition_signature_invalid")
        );
    }

    #[test]
    fn verify_rejects_key_mismatch() {
        let s = sign_authority_transition(transition(), &key(), KEY_ID).unwrap();
        assert_eq!(
            verify_authority_transition(&s, &key(), "other").unwrap_err(),
            WorkflowCapabilityError("authority_transition_key_mismatch")
        );
    }

    #[test]
    fn encode_decode_canonical_round_trip() {
        let s = sign_authority_transition(transition(), &key(), KEY_ID).unwrap();
        let enc = encode_signed_authority_transition(&s).unwrap();
        let back = decode_signed_authority_transition(&enc).unwrap();
        assert_eq!(back.transition.sequence, 0);
        assert_eq!(back.transition.transition_kind, "issued");
    }

    #[test]
    fn transition_sha256_stable() {
        let s = sign_authority_transition(transition(), &key(), KEY_ID).unwrap();
        let d = authority_transition_sha256(&s).unwrap();
        assert_eq!(d.len(), 64);
        assert!(d.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn invalid_kind_rejected() {
        let res = WorkflowCapabilityAuthorityTransition::new(
            0,
            "cap-1",
            "a".repeat(64),
            0,
            "bogus",
            ZERO_TRANSITION_SHA256,
            "b".repeat(64),
            None,
            None,
            None,
            "2026-10-02T00:00:00.000000Z",
            None,
            None,
            None,
        );
        assert_eq!(
            res.unwrap_err(),
            WorkflowCapabilityError("invalid_transition_kind")
        );
    }
}
