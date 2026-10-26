//! The proof-free local trust claim, and the names it is known by.
//!
//! `trust_claim_hash` and `trust_attestation_replay_key` in
//! `runtime/trust_attestation.py` name a claim and an attestation so that a
//! verifier can recognize the one it has already seen. Both names are the
//! SHA-256 of a canonical payload, so a Rust twin that admitted one claim more
//! or one claim fewer than Python would hand the verifier a name for something
//! nobody had attested.
//!
//! `validated_local_trust_claim` is the gate those names are taken through: it
//! admits only a claim that says it was derived on this device, carries
//! evidence that hashes to the digest it advertises, and has had every prior
//! attestation stripped from its metadata. Anything else is rejected rather
//! than normalized.

use serde_json::{Map, Value};

use crate::attestation_timestamp::parse_attestation_timestamp;
use crate::evidence_hash::guard_evidence_hash;

/// `_PRIOR_ATTESTATION_METADATA_KEYS`: a prior signature never rides along.
const PRIOR_ATTESTATION_METADATA_KEYS: [&str; 4] = [
    "attestation",
    "attestationBindings",
    "attestationRef",
    "attestationVerification",
];

/// The fields `trust_attestation_replay_key` names an attestation by.
const REPLAY_KEY_FIELDS: [&str; 7] = [
    "domainSeparator",
    "nonce",
    "itemId",
    "scope",
    "layerId",
    "workspaceId",
    "repositoryId",
];

/// The claim was not locally derived, or its evidence did not hold up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrustClaimRejected;

impl std::fmt::Display for TrustClaimRejected {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Trust claim is not locally derived or has invalid evidence")
    }
}

impl std::error::Error for TrustClaimRejected {}

/// `_validated_local_trust_claim(raw_claim, require_layer_identity=...)`.
#[must_use]
pub fn validated_local_trust_claim(
    raw_claim: &Value,
    require_layer_identity: bool,
) -> Option<Map<String, Value>> {
    let claim = raw_claim.as_object()?;
    let provenance = claim.get("provenance")?.as_object()?;
    if provenance.get("origin").and_then(Value::as_str) != Some("hol-guard-local")
        || provenance.get("verificationStatus").and_then(Value::as_str) != Some("locally_derived")
    {
        return None;
    }
    if !is_non_empty_string(provenance.get("derivation")) {
        return None;
    }
    if claim.get("evidenceAuthority").and_then(Value::as_str) != Some("device_claim")
        || claim.get("affectsV4Score") != Some(&Value::Bool(false))
    {
        return None;
    }
    // `capturedAt` has to be an instant, not merely present.
    match claim.get("capturedAt").and_then(Value::as_str) {
        Some(captured_at) if parse_attestation_timestamp(captured_at).is_some() => {}
        _ => return None,
    }
    if require_layer_identity {
        if !is_non_empty_string(claim.get("layerId"))
            || !is_non_empty_string(claim.get("layerType"))
        {
            return None;
        }
    } else if claim.get("resolutionSource").and_then(Value::as_str) != Some("local") {
        return None;
    }
    let raw_metadata = claim.get("metadata")?.as_object()?;
    let evidence = raw_metadata.get("evidence")?.as_object()?;
    // The advertised digest has to be the one the evidence actually hashes to.
    if raw_metadata.get("evidenceHash").and_then(Value::as_str)
        != Some(guard_evidence_hash(evidence).as_str())
    {
        return None;
    }
    match raw_metadata
        .get("evidenceSchemaVersion")
        .and_then(Value::as_str)
    {
        Some(version) if version.starts_with("guard-aibom-") => {}
        _ => return None,
    }
    let mut metadata: Map<String, Value> = raw_metadata
        .iter()
        .filter(|(key, _)| !PRIOR_ATTESTATION_METADATA_KEYS.contains(&key.as_str()))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    metadata.insert(
        "attestationStatus".to_owned(),
        Value::String("unsigned".to_owned()),
    );
    let mut normalized = claim.clone();
    normalized.insert("metadata".to_owned(), Value::Object(metadata));
    Some(normalized)
}

/// `trust_claim_hash(claim, require_layer_identity=...)`.
///
/// # Errors
///
/// Returns [`TrustClaimRejected`] when the claim does not pass the gate above.
pub fn trust_claim_hash(
    claim: &Map<String, Value>,
    require_layer_identity: bool,
) -> Result<String, TrustClaimRejected> {
    let normalized =
        validated_local_trust_claim(&Value::Object(claim.clone()), require_layer_identity)
            .ok_or(TrustClaimRejected)?;
    Ok(guard_evidence_hash(&normalized))
}

/// `trust_attestation_replay_key(payload)`: the verifier-side replay identity.
///
/// Python builds the hashed object with `payload.get(field)`, so a field the
/// attestation never carried is hashed as an explicit `null` rather than left
/// out — two payloads differing only in an absent versus null field share a key.
#[must_use]
pub fn trust_attestation_replay_key(payload: &Map<String, Value>) -> String {
    let identity: Map<String, Value> = REPLAY_KEY_FIELDS
        .iter()
        .map(|field| {
            (
                (*field).to_owned(),
                payload.get(*field).cloned().unwrap_or(Value::Null),
            )
        })
        .collect();
    guard_evidence_hash(&identity)
}

fn is_non_empty_string(value: Option<&Value>) -> bool {
    matches!(value.and_then(Value::as_str), Some(text) if !text.is_empty())
}
