//! `trust_attestation_shape` runner-authority kind: the shape checks
//! `runtime/trust_attestation.py` runs before it signs anything.
//!
//! The signer keeps the key and the signature in Python. What it asks here is
//! which inventory claims are locally derived, the name each survivor is signed
//! under, and whether a payload is one the verifier will accept. The answers
//! come from the same [`guard_command`] functions the verifier uses, so a claim
//! or payload the signer accepts is one the verifier reads the same way.
//!
//! - `{"op": "claims", "resolution": ..., "layers": ...}` answers
//!   `{"resolution": {"claim", "claim_hash"} | null, "layers": [...]}`: the
//!   `trustResolution` claim and the `trustLayers` claims that pass the local
//!   gate, each with its normalized metadata and claim hash. A `layers` value
//!   that is not a list carries no layers.
//! - `{"op": "claim_hash", "claim": {...}, "require_layer_identity": bool}`
//!   answers `{"claim_hash": str | null}`, `null` when the gate refuses it.
//! - `{"op": "payload", "payload": {...}, "require_signed_at": bool,
//!   "require_nonce": bool, "require_subject_bindings": bool}` answers
//!   `{"payload": {...}}` with the normalized payload, or `{"refused": str}`
//!   with the message the signer raises.

use guard_command::attestation_payload::{validate_attestation_payload, AttestationPayloadRules};
use guard_command::trust_claim::{trust_claim_hash, validated_local_trust_claim};
use serde_json::{json, Map, Value};

use crate::runner_authority_detector::args_object;
use crate::runner_authority_op::{KindResult, ERR_INVALID};

pub(crate) fn dispatch(args: &Value) -> KindResult {
    let args = args_object(args)?;
    match args.get("op").and_then(Value::as_str) {
        Some("claims") => claims(args),
        Some("claim_hash") => claim_hash(args),
        Some("payload") => payload(args),
        _ => Err(ERR_INVALID),
    }
}

fn flag(args: &Map<String, Value>, key: &str) -> Result<bool, &'static str> {
    args.get(key).and_then(Value::as_bool).ok_or(ERR_INVALID)
}

/// The claim the gate admits and the name it is signed under, or `null`.
fn admitted(raw: &Value, require_layer_identity: bool) -> KindResult {
    let Some(claim) = validated_local_trust_claim(raw, require_layer_identity) else {
        return Ok(Value::Null);
    };
    // An admitted claim is admitted again unchanged, so its hash always exists.
    let hash = trust_claim_hash(&claim, require_layer_identity).map_err(|_| ERR_INVALID)?;
    Ok(json!({ "claim": claim, "claim_hash": hash }))
}

fn claims(args: &Map<String, Value>) -> KindResult {
    let resolution = admitted(args.get("resolution").unwrap_or(&Value::Null), false)?;
    let mut layers = Vec::new();
    if let Some(Value::Array(raw_layers)) = args.get("layers") {
        for raw in raw_layers {
            let layer = admitted(raw, true)?;
            if !layer.is_null() {
                layers.push(layer);
            }
        }
    }
    Ok(json!({ "resolution": resolution, "layers": layers }))
}

fn claim_hash(args: &Map<String, Value>) -> KindResult {
    let claim = args
        .get("claim")
        .and_then(Value::as_object)
        .ok_or(ERR_INVALID)?;
    let require_layer_identity = flag(args, "require_layer_identity")?;
    let hash = trust_claim_hash(claim, require_layer_identity).ok();
    Ok(json!({ "claim_hash": hash }))
}

fn payload(args: &Map<String, Value>) -> KindResult {
    let payload = args
        .get("payload")
        .and_then(Value::as_object)
        .ok_or(ERR_INVALID)?;
    let rules = AttestationPayloadRules {
        require_signed_at: flag(args, "require_signed_at")?,
        require_nonce: flag(args, "require_nonce")?,
        require_subject_bindings: flag(args, "require_subject_bindings")?,
    };
    Ok(match validate_attestation_payload(payload, rules) {
        Ok(normalized) => json!({ "payload": normalized }),
        Err(refused) => json!({ "refused": refused.message() }),
    })
}

#[cfg(test)]
#[path = "trust_attestation_shape_tests.rs"]
mod tests;
