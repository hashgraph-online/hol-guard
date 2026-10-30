//! Full verification of one Pulse receipt against one held Guard action.
//!
//! The order follows Pulse's enforcement checklist: the Yanez signature, the
//! claims, the approver's signature and envelope, the terms, the user key
//! registry, the assurance floor, then freshness. Single-use consumption is
//! the caller's last step, after this returns `Ok`.

use serde_json::{Map, Value};

use crate::jws::{self, JwkSet};
use crate::strict_json::{safe_integer, terms_equal};
use crate::user_sig;
use crate::{AssuranceTier, PulseError};

/// A decision may be dated at most this far in the future.
pub const MAX_FUTURE_SKEW_SECONDS: i64 = 60;
/// Oldest approval Guard accepts: Pulse's recommended `max_age_seconds`.
/// Guard verifies a receipt seconds after it arrives, so this is a backstop.
pub const DEFAULT_MAX_AGE_SECONDS: i64 = 900;

/// One key from `GET /api/agent/user_keys`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisteredUserKey {
    /// Lower-case hex of the 48-byte compressed key, without `0x`.
    pub public_key_hex: String,
    /// Highest tier this key can sign at, or `None` when it cannot sign.
    pub tier: Option<AssuranceTier>,
}

/// Everything Guard pins or expects for one receipt.
#[derive(Debug, Clone)]
pub struct ReceiptPolicy<'a> {
    /// Pinned issuer. `None` only for the enrollment receipt, which is where
    /// Guard learns the issuer it pins from then on.
    pub expected_issuer: Option<&'a str>,
    pub expected_yid: &'a str,
    /// Pinned agent key id. `None` only for the enrollment receipt.
    pub expected_agent_key_id: Option<&'a str>,
    pub expected_request_id: &'a str,
    pub expected_terms: &'a Value,
    pub min_tier: AssuranceTier,
    pub max_age_seconds: i64,
    /// Keys the registry lists for the pinned YID, read at verification time.
    pub registered_keys: &'a [RegisteredUserKey],
    pub now_epoch: i64,
}

/// What Guard learns from a receipt that passed every check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedReceipt {
    pub jti: String,
    pub yid: String,
    pub issuer: String,
    pub agent_key_id: String,
    pub tier: AssuranceTier,
    pub decided_at: i64,
    pub consent_not_after: i64,
    pub user_public_key_hex: String,
}

fn string_claim<'a>(claims: &'a Map<String, Value>, name: &str) -> Option<&'a str> {
    claims
        .get(name)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
}

fn int_claim(claims: &Map<String, Value>, name: &str) -> Option<i64> {
    claims.get(name).and_then(safe_integer)
}

/// Verify `artifact` for the action described by `policy`.
pub fn verify_receipt(
    artifact: &str,
    keys: &JwkSet,
    policy: &ReceiptPolicy<'_>,
) -> Result<VerifiedReceipt, PulseError> {
    if !policy.min_tier.is_allowed_floor() || policy.max_age_seconds <= 0 {
        return Err(PulseError::InvalidRequest("policy"));
    }
    let verified = jws::verify(artifact, keys)?;
    let claims = &verified.claims;
    let missing = PulseError::ReceiptInvalid("claims");

    // Claims the receipt must carry, in Pulse's types.
    let iss = string_claim(claims, "iss").ok_or(missing.clone())?;
    let sub = string_claim(claims, "sub").ok_or(missing.clone())?;
    let jti = string_claim(claims, "jti").ok_or(missing.clone())?;
    let agent_key_id = string_claim(claims, "yanez_agent_key_id").ok_or(missing.clone())?;
    if claims.get("yanez_decision").and_then(Value::as_str) != Some("approved") {
        return Err(PulseError::ReceiptInvalid("decision"));
    }
    let iat = int_claim(claims, "iat").ok_or(missing.clone())?;
    let decided_at = int_claim(claims, "yanez_decided_at").ok_or(missing.clone())?;
    if iat != decided_at {
        return Err(PulseError::ReceiptInvalid("iat"));
    }
    if decided_at > policy.now_epoch + MAX_FUTURE_SKEW_SECONDS {
        return Err(PulseError::ReceiptInvalid("future"));
    }
    match int_claim(claims, "yanez_match_overlap") {
        Some(v) if v >= 0 => {}
        _ => return Err(missing),
    }
    // Guard always sets a consent bound when it creates a request, so a
    // receipt without one was not created by this Guard.
    let consent_not_after = int_claim(claims, "yanez_consent_not_after")
        .ok_or(PulseError::ReceiptInvalid("consent"))?;
    let terms = claims
        .get("yanez_terms")
        .filter(|t| t.is_object())
        .ok_or(PulseError::ReceiptInvalid("terms"))?;
    let tier = claims
        .get("yanez_assurance_tier")
        .and_then(Value::as_str)
        .and_then(AssuranceTier::parse)
        .ok_or(PulseError::ReceiptInvalid("tier"))?;

    // Pinned identities. The issuer is compared with Guard's configured
    // value, never one read from the token.
    if policy
        .expected_issuer
        .is_some_and(|expected| iss != expected)
    {
        return Err(PulseError::WrongIssuer);
    }
    if sub != policy.expected_yid {
        return Err(PulseError::WrongYid);
    }
    if policy
        .expected_agent_key_id
        .is_some_and(|expected| agent_key_id != expected)
    {
        return Err(PulseError::WrongAgentKey);
    }
    if jti != policy.expected_request_id {
        return Err(PulseError::WrongRequest);
    }

    // The approver's signature, and every field in it against the receipt.
    let proof = |name: &str| {
        claims
            .get(name)
            .and_then(Value::as_str)
            .ok_or(PulseError::UserSignatureInvalid("proof_claims"))
    };
    let envelope = user_sig::verify(
        proof("yanez_user_sig_alg")?,
        proof("yanez_user_public_key")?,
        proof("yanez_user_signature")?,
        proof("yanez_signed_message")?,
    )?;
    check_envelope(
        &envelope.fields,
        iss,
        sub,
        jti,
        tier,
        consent_not_after,
        terms,
    )?;

    // Terms: the receipt, the signed envelope and Guard's own copy all agree.
    if !terms_equal(terms, policy.expected_terms) {
        return Err(PulseError::TermsMismatch);
    }

    // The approving key must still be registered to the pinned YID, at a tier
    // that covers the one it signed. A key removed from the registry (a lost
    // or rotated device) stops verifying here.
    let registered = policy
        .registered_keys
        .iter()
        .find(|k| k.public_key_hex == envelope.public_key_hex)
        .ok_or(PulseError::UserKeyNotRegistered)?;
    match registered.tier {
        Some(max) if max >= tier => {}
        _ => return Err(PulseError::UserKeyNotRegistered),
    }

    if tier < policy.min_tier {
        return Err(PulseError::AssuranceTooLow);
    }
    if policy.now_epoch - decided_at > policy.max_age_seconds {
        return Err(PulseError::Stale);
    }
    if policy.now_epoch > consent_not_after {
        return Err(PulseError::ConsentExpired);
    }
    Ok(VerifiedReceipt {
        jti: jti.to_owned(),
        yid: sub.to_owned(),
        issuer: iss.to_owned(),
        agent_key_id: agent_key_id.to_owned(),
        tier,
        decided_at,
        consent_not_after,
        user_public_key_hex: envelope.public_key_hex,
    })
}

fn check_envelope(
    fields: &Map<String, Value>,
    iss: &str,
    sub: &str,
    jti: &str,
    tier: AssuranceTier,
    consent_not_after: i64,
    terms: &Value,
) -> Result<(), PulseError> {
    let bad = |what: &'static str| PulseError::UserSignatureInvalid(what);
    let text = |name: &str| fields.get(name).and_then(Value::as_str);
    if fields.get("version").and_then(safe_integer) != Some(1) {
        return Err(bad("envelope_version"));
    }
    if text("action") != Some(user_sig::ENVELOPE_ACTION) {
        return Err(bad("envelope_action"));
    }
    if text("decision") != Some("approve") {
        return Err(bad("envelope_decision"));
    }
    if text("issuer") != Some(iss) {
        return Err(bad("envelope_issuer"));
    }
    if text("yid") != Some(sub) {
        return Err(bad("envelope_yid"));
    }
    if text("authorization_request_id") != Some(jti) {
        return Err(bad("envelope_request"));
    }
    if text("assurance_tier") != Some(tier.as_str()) {
        return Err(bad("envelope_tier"));
    }
    if fields.get("consent_not_after").and_then(safe_integer) != Some(consent_not_after) {
        return Err(bad("envelope_consent"));
    }
    if fields.get("signed_at").and_then(safe_integer).is_none() {
        return Err(bad("envelope_signed_at"));
    }
    match fields.get("terms") {
        Some(signed) if terms_equal(signed, terms) => Ok(()),
        _ => Err(bad("envelope_terms")),
    }
}

#[cfg(test)]
#[path = "receipt_tests.rs"]
mod tests;
