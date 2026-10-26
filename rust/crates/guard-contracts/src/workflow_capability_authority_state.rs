//! `workflow_capability_authority_state.py` — authenticated mutable
//! authority-state and append-only revocation contracts (RTM-013, pure half).
//!
//! `WorkflowCapabilityAuthorityState` is the mutable high-water record
//! (`use_high_water`, `revision`, `observed_at`, optional `revocation_id`/
//! `revoked_at`); `WorkflowCapabilityRevocation` is the immutable tombstone.
//! Each is signed over the framed `{key_id, payload}` envelope with HMAC-SHA256
//! (`purpose` = `authority-state` / `revocation`) and encode/decode round-trips
//! canonical JSON so a persisted row can be re-verified byte-for-byte.
//!
//! The store half (`create_authority_state` / `advance_authority_state` /
//! `append_revocation` / `_write_state` / `_load_revocation`) lives in
//! `guard-runtime` atop `rusqlite`.

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::Sha256;

use crate::canonical_json::write_canonical_json;
use crate::workflow_capability::{
    canonical_framed_payload, validate_workflow_capability_identifier, WorkflowCapabilityError,
};

pub const AUTHORITY_STATE_SCHEMA: &str = "hol-guard.workflow-capability-authority-state.v1";
pub const REVOCATION_SCHEMA: &str = "hol-guard.workflow-capability-revocation.v1";

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

/// `_SHA256.fullmatch` + `_digest`.
fn validate_digest(v: &str, name: &'static str) -> WfResult<()> {
    if is_sha256(v) {
        Ok(())
    } else {
        err(name)
    }
}

/// `_TIMESTAMP_PATTERN` + `parse_utc_timestamp` (delegates to the claim-side
/// canonical-timestamp check to keep one definition).
fn validate_timestamp(v: &str) -> WfResult<()> {
    // Reuse the strict shape check: canonical UTC `…T…….NNNNNNZ`.
    let ok = {
        let b = v.as_bytes();
        b.len() == 27
            && b[4] == b'-'
            && b[7] == b'-'
            && b[10] == b'T'
            && b[13] == b':'
            && b[16] == b':'
            && b[19] == b'.'
            && b[26] == b'Z'
            && [
                0usize, 1, 2, 3, 5, 6, 8, 9, 11, 12, 14, 15, 17, 18, 20, 21, 22, 23, 24, 25,
            ]
            .iter()
            .all(|&i| b[i].is_ascii_digit())
    };
    if ok {
        Ok(())
    } else {
        err("invalid_canonical_timestamp")
    }
}

/// `[a-z][a-z0-9_.-]{0,63}` reason-code pattern.
fn validate_reason_code(v: &str) -> WfResult<()> {
    let ok = !v.is_empty()
        && v.len() <= 64
        && v.chars().next().is_some_and(|c| c.is_ascii_lowercase())
        && v.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '_' | '.' | '-'));
    if ok {
        Ok(())
    } else {
        err("invalid_reason_code")
    }
}

// ─── authority state ─────────────────────────────────────────────────────

/// `WorkflowCapabilityAuthorityState`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WorkflowCapabilityAuthorityState {
    pub schema_version: String,
    pub capability_id: String,
    pub claim_sha256: String,
    pub use_high_water: i64,
    pub observed_at: String,
    pub revision: i64,
    pub revocation_id: Option<String>,
    pub revoked_at: Option<String>,
}

impl WorkflowCapabilityAuthorityState {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        capability_id: impl Into<String>,
        claim_sha256: impl Into<String>,
        use_high_water: i64,
        observed_at: impl Into<String>,
        revision: i64,
        revocation_id: Option<String>,
        revoked_at: Option<String>,
    ) -> WfResult<Self> {
        let s = Self {
            schema_version: AUTHORITY_STATE_SCHEMA.to_string(),
            capability_id: capability_id.into(),
            claim_sha256: claim_sha256.into(),
            use_high_water,
            observed_at: observed_at.into(),
            revision,
            revocation_id,
            revoked_at,
        };
        s.validate()?;
        Ok(s)
    }

    fn validate(&self) -> WfResult<()> {
        if self.schema_version != AUTHORITY_STATE_SCHEMA {
            return err("unsupported_authority_state_schema");
        }
        validate_workflow_capability_identifier("capability_id", &self.capability_id)?;
        validate_digest(&self.claim_sha256, "invalid_claim_sha256")?;
        validate_timestamp(&self.observed_at)?;
        if self.use_high_water < 0 {
            return err("invalid_use_high_water");
        }
        if self.revision < 0 {
            return err("invalid_revision");
        }
        match (&self.revocation_id, &self.revoked_at) {
            (Some(id), Some(at)) => {
                validate_workflow_capability_identifier("revocation_id", id)?;
                validate_timestamp(at)?;
            }
            (None, None) => {}
            _ => return err("authority_state_revocation_incomplete"),
        }
        Ok(())
    }

    /// `from_dict` — strict key set.
    pub fn decode(payload: &Value) -> WfResult<Self> {
        let m = strict_object(
            payload,
            &[
                "schema_version",
                "capability_id",
                "claim_sha256",
                "use_high_water",
                "observed_at",
                "revision",
                "revocation_id",
                "revoked_at",
            ],
        )?;
        let s = Self {
            schema_version: string_field("schema_version", m)?,
            capability_id: string_field("capability_id", m)?,
            claim_sha256: string_field("claim_sha256", m)?,
            use_high_water: integer_field("use_high_water", m)?,
            observed_at: string_field("observed_at", m)?,
            revision: integer_field("revision", m)?,
            revocation_id: optional_string_field("revocation_id", m)?,
            revoked_at: optional_string_field("revoked_at", m)?,
        };
        s.validate()?;
        Ok(s)
    }

    pub fn to_value(&self) -> Value {
        let mut m = Map::new();
        m.insert(
            "schema_version".into(),
            Value::String(self.schema_version.clone()),
        );
        m.insert(
            "capability_id".into(),
            Value::String(self.capability_id.clone()),
        );
        m.insert(
            "claim_sha256".into(),
            Value::String(self.claim_sha256.clone()),
        );
        m.insert("use_high_water".into(), Value::from(self.use_high_water));
        m.insert(
            "observed_at".into(),
            Value::String(self.observed_at.clone()),
        );
        m.insert("revision".into(), Value::from(self.revision));
        m.insert(
            "revocation_id".into(),
            self.revocation_id
                .clone()
                .map(Value::String)
                .unwrap_or(Value::Null),
        );
        m.insert(
            "revoked_at".into(),
            self.revoked_at
                .clone()
                .map(Value::String)
                .unwrap_or(Value::Null),
        );
        Value::Object(m)
    }
}

// ─── revocation ──────────────────────────────────────────────────────────

/// `WorkflowCapabilityRevocation`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WorkflowCapabilityRevocation {
    pub schema_version: String,
    pub revocation_id: String,
    pub capability_id: String,
    pub claim_sha256: String,
    pub reason_code: String,
    pub revoked_at: String,
}

impl WorkflowCapabilityRevocation {
    pub fn new(
        revocation_id: impl Into<String>,
        capability_id: impl Into<String>,
        claim_sha256: impl Into<String>,
        reason_code: impl Into<String>,
        revoked_at: impl Into<String>,
    ) -> WfResult<Self> {
        let r = Self {
            schema_version: REVOCATION_SCHEMA.to_string(),
            revocation_id: revocation_id.into(),
            capability_id: capability_id.into(),
            claim_sha256: claim_sha256.into(),
            reason_code: reason_code.into(),
            revoked_at: revoked_at.into(),
        };
        r.validate()?;
        Ok(r)
    }

    fn validate(&self) -> WfResult<()> {
        if self.schema_version != REVOCATION_SCHEMA {
            return err("unsupported_revocation_schema");
        }
        validate_workflow_capability_identifier("revocation_id", &self.revocation_id)?;
        validate_workflow_capability_identifier("capability_id", &self.capability_id)?;
        validate_digest(&self.claim_sha256, "invalid_claim_sha256")?;
        validate_reason_code(&self.reason_code)?;
        validate_timestamp(&self.revoked_at)?;
        Ok(())
    }

    pub fn decode(payload: &Value) -> WfResult<Self> {
        let m = strict_object(
            payload,
            &[
                "schema_version",
                "revocation_id",
                "capability_id",
                "claim_sha256",
                "reason_code",
                "revoked_at",
            ],
        )?;
        let r = Self {
            schema_version: string_field("schema_version", m)?,
            revocation_id: string_field("revocation_id", m)?,
            capability_id: string_field("capability_id", m)?,
            claim_sha256: string_field("claim_sha256", m)?,
            reason_code: string_field("reason_code", m)?,
            revoked_at: string_field("revoked_at", m)?,
        };
        r.validate()?;
        Ok(r)
    }

    pub fn to_value(&self) -> Value {
        let mut m = Map::new();
        m.insert(
            "schema_version".into(),
            Value::String(self.schema_version.clone()),
        );
        m.insert(
            "revocation_id".into(),
            Value::String(self.revocation_id.clone()),
        );
        m.insert(
            "capability_id".into(),
            Value::String(self.capability_id.clone()),
        );
        m.insert(
            "claim_sha256".into(),
            Value::String(self.claim_sha256.clone()),
        );
        m.insert(
            "reason_code".into(),
            Value::String(self.reason_code.clone()),
        );
        m.insert("revoked_at".into(), Value::String(self.revoked_at.clone()));
        Value::Object(m)
    }
}

// ─── signed envelopes ────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub struct SignedAuthorityState {
    pub state: WorkflowCapabilityAuthorityState,
    pub key_id: String,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SignedRevocation {
    pub revocation: WorkflowCapabilityRevocation,
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

fn mac_hex(purpose: &str, payload: &Value, key: &[u8], key_id: &str) -> WfResult<String> {
    validate_key(key)?;
    validate_workflow_capability_identifier("key_id", key_id)?;
    let mut env = Map::new();
    env.insert("key_id".into(), Value::String(key_id.to_string()));
    env.insert("payload".into(), payload.clone());
    let framed = canonical_framed_payload(purpose, &Value::Object(env))?;
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("hmac any len");
    mac.update(&framed);
    Ok(hex_lower(&mac.finalize().into_bytes()))
}

fn verify_envelope(
    actual_key: &str,
    actual: &str,
    expected: &str,
    key_id: &str,
    mismatch: &'static str,
    invalid: &'static str,
) -> WfResult<()> {
    if actual_key != key_id {
        return err(mismatch);
    }
    if !is_sha256(actual) {
        return err("invalid_signature");
    }
    if !constant_time_eq(actual.as_bytes(), expected.as_bytes()) {
        return err(invalid);
    }
    Ok(())
}

pub fn sign_authority_state(
    state: WorkflowCapabilityAuthorityState,
    key: &[u8],
    key_id: &str,
) -> WfResult<SignedAuthorityState> {
    let signature = mac_hex("authority-state", &state.to_value(), key, key_id)?;
    Ok(SignedAuthorityState {
        state,
        key_id: key_id.to_string(),
        signature,
    })
}

pub fn verify_authority_state(
    signed: &SignedAuthorityState,
    key: &[u8],
    key_id: &str,
) -> WfResult<()> {
    let expected = sign_authority_state(signed.state.clone(), key, key_id)?.signature;
    verify_envelope(
        &signed.key_id,
        &signed.signature,
        &expected,
        key_id,
        "authority_state_key_mismatch",
        "authority_state_signature_invalid",
    )
}

pub fn sign_revocation(
    revocation: WorkflowCapabilityRevocation,
    key: &[u8],
    key_id: &str,
) -> WfResult<SignedRevocation> {
    let signature = mac_hex("revocation", &revocation.to_value(), key, key_id)?;
    Ok(SignedRevocation {
        revocation,
        key_id: key_id.to_string(),
        signature,
    })
}

pub fn verify_revocation(signed: &SignedRevocation, key: &[u8], key_id: &str) -> WfResult<()> {
    let expected = sign_revocation(signed.revocation.clone(), key, key_id)?.signature;
    verify_envelope(
        &signed.key_id,
        &signed.signature,
        &expected,
        key_id,
        "revocation_key_mismatch",
        "revocation_signature_invalid",
    )
}

// ─── canonical encode/decode ─────────────────────────────────────────────

fn canonical(v: &Value) -> WfResult<String> {
    let mut buf = Vec::new();
    write_canonical_json(v, &mut buf)
        .map_err(|_| WorkflowCapabilityError("invalid_canonical_payload"))?;
    String::from_utf8(buf).map_err(|_| WorkflowCapabilityError("invalid_canonical_payload"))
}

pub fn encode_signed_authority_state(signed: &SignedAuthorityState) -> WfResult<String> {
    let mut env = Map::new();
    env.insert("key_id".into(), Value::String(signed.key_id.clone()));
    env.insert("signature".into(), Value::String(signed.signature.clone()));
    env.insert("state".into(), signed.state.to_value());
    canonical(&Value::Object(env))
}

pub fn decode_signed_authority_state(encoded: &str) -> WfResult<SignedAuthorityState> {
    let payload: Value = serde_json::from_str(encoded)
        .map_err(|_| WorkflowCapabilityError("authority_state_payload_invalid"))?;
    let m = strict_object(&payload, &["key_id", "signature", "state"])
        .map_err(|_| WorkflowCapabilityError("authority_state_payload_invalid"))?;
    let signed = SignedAuthorityState {
        state: WorkflowCapabilityAuthorityState::decode(require(m, "state")?)?,
        key_id: require_str(m, "key_id")?,
        signature: require_str(m, "signature")?,
    };
    if encode_signed_authority_state(&signed)? != encoded {
        return err("authority_state_not_canonical");
    }
    Ok(signed)
}

pub fn encode_signed_revocation(signed: &SignedRevocation) -> WfResult<String> {
    let mut env = Map::new();
    env.insert("key_id".into(), Value::String(signed.key_id.clone()));
    env.insert("revocation".into(), signed.revocation.to_value());
    env.insert("signature".into(), Value::String(signed.signature.clone()));
    canonical(&Value::Object(env))
}

pub fn decode_signed_revocation(encoded: &str) -> WfResult<SignedRevocation> {
    let payload: Value = serde_json::from_str(encoded)
        .map_err(|_| WorkflowCapabilityError("revocation_payload_invalid"))?;
    let m = strict_object(&payload, &["key_id", "revocation", "signature"])
        .map_err(|_| WorkflowCapabilityError("revocation_payload_invalid"))?;
    let signed = SignedRevocation {
        revocation: WorkflowCapabilityRevocation::decode(require(m, "revocation")?)?,
        key_id: require_str(m, "key_id")?,
        signature: require_str(m, "signature")?,
    };
    if encode_signed_revocation(&signed)? != encoded {
        return err("revocation_not_canonical");
    }
    Ok(signed)
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

fn name_err(name: &'static str) -> &'static str {
    match name {
        "schema_version" => "invalid_schema_version",
        "capability_id" => "invalid_capability_id",
        "claim_sha256" => "invalid_claim_sha256",
        "use_high_water" => "invalid_use_high_water",
        "observed_at" => "invalid_observed_at",
        "revision" => "invalid_revision",
        "revocation_id" => "invalid_revocation_id",
        "revoked_at" => "invalid_revoked_at",
        "reason_code" => "invalid_reason_code",
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
    const TS: &str = "2026-10-02T00:00:00.000000Z";

    fn state() -> WorkflowCapabilityAuthorityState {
        WorkflowCapabilityAuthorityState::new("cap-1", "a".repeat(64), 0, TS, 0, None, None)
            .unwrap()
    }

    #[test]
    fn authority_state_sign_verify_round_trip() {
        let s = sign_authority_state(state(), &key(), KEY_ID).unwrap();
        verify_authority_state(&s, &key(), KEY_ID).unwrap();
    }

    #[test]
    fn authority_state_encode_decode_canonical() {
        let s = sign_authority_state(state(), &key(), KEY_ID).unwrap();
        let enc = encode_signed_authority_state(&s).unwrap();
        let back = decode_signed_authority_state(&enc).unwrap();
        assert_eq!(back.state.revision, 0);
    }

    #[test]
    fn authority_state_revocation_incomplete_rejected() {
        let res = WorkflowCapabilityAuthorityState::new(
            "cap-1",
            "a".repeat(64),
            0,
            TS,
            0,
            Some("rev-1".into()),
            None,
        );
        assert_eq!(
            res.unwrap_err(),
            WorkflowCapabilityError("authority_state_revocation_incomplete")
        );
    }

    #[test]
    fn revocation_sign_verify_round_trip() {
        let r = WorkflowCapabilityRevocation::new("rev-1", "cap-1", "a".repeat(64), "consumed", TS)
            .unwrap();
        let s = sign_revocation(r, &key(), KEY_ID).unwrap();
        verify_revocation(&s, &key(), KEY_ID).unwrap();
    }

    #[test]
    fn revocation_encode_decode_canonical() {
        let r = WorkflowCapabilityRevocation::new("rev-1", "cap-1", "a".repeat(64), "consumed", TS)
            .unwrap();
        let s = sign_revocation(r, &key(), KEY_ID).unwrap();
        let enc = encode_signed_revocation(&s).unwrap();
        let back = decode_signed_revocation(&enc).unwrap();
        assert_eq!(back.revocation.reason_code, "consumed");
    }

    #[test]
    fn revocation_bad_reason_code_rejected() {
        let res =
            WorkflowCapabilityRevocation::new("rev-1", "cap-1", "a".repeat(64), "BAD CODE", TS);
        assert_eq!(
            res.unwrap_err(),
            WorkflowCapabilityError("invalid_reason_code")
        );
    }

    #[test]
    fn verify_rejects_key_mismatch() {
        let s = sign_authority_state(state(), &key(), KEY_ID).unwrap();
        assert_eq!(
            verify_authority_state(&s, &key(), "other").unwrap_err(),
            WorkflowCapabilityError("authority_state_key_mismatch")
        );
    }
}
