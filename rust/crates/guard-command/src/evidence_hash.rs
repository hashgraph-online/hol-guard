//! The digest a locally derived trust claim is named by.
//!
//! `runtime.evidence_hash` in Python and this module hash the same payload on
//! two different routes: a claim written on one route is looked up, replayed
//! and compared on the other, so a digest that differed by a single byte would
//! read as a claim nobody had ever made. The canonical encoding below is the
//! shared one `guard-contracts` already writes for CPython's
//! `json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=True)`.

use guard_contracts::write_canonical_json;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::aibom_trust_metadata::GuardEvidenceHashApi;

/// `canonical_guard_evidence_payload(payload)`: the exact bytes that get hashed.
#[must_use]
pub fn canonical_guard_evidence_payload(payload: &Map<String, Value>) -> Vec<u8> {
    let mut encoded = Vec::new();
    // A `Value` holds no NaN and no lone surrogate, and the writer is
    // unbounded here, so the canonical encoding of one cannot fail.
    write_canonical_json(&Value::Object(payload.clone()), &mut encoded)
        .expect("a json value is always canonically encodable");
    encoded
}

/// `guard_evidence_hash(payload)`.
#[must_use]
pub fn guard_evidence_hash(payload: &Map<String, Value>) -> String {
    hex::encode(Sha256::digest(canonical_guard_evidence_payload(payload)))
}

/// The native answer for the `.runtime.evidence_hash` seam.
pub struct NativeGuardEvidenceHash;

impl GuardEvidenceHashApi for NativeGuardEvidenceHash {
    fn guard_evidence_hash(&self, payload: &Map<String, Value>) -> String {
        guard_evidence_hash(payload)
    }
}
