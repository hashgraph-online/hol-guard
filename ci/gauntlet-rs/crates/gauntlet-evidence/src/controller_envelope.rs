//! Python-compatible Ed25519 envelope reader for private controller records.
//! The public key must be pinned outside the candidate and producer record.

use crate::crypto::{decode_base64, verify_ed25519};
use crate::{canonical_value, EvidenceError, Result};
use gauntlet_contracts::canonicalize;
use serde_json::Value;

const INVALID: EvidenceError = EvidenceError::Invalid("invalid controller envelope");
const BAD_SIGNATURE: EvidenceError =
    EvidenceError::Invalid("externally pinned controller signature invalid");

/// Verify the exact `{"record": ..., "signature": base64}` format used by
/// Python `developer_product_custody._signed`. Bounded JSON parsing rejects
/// duplicate keys before signature verification. This authenticates only the
/// envelope record, not the SDK, kernel or product effects it describes.
pub fn verify_controller_envelope(raw: &[u8], external_public_key: &[u8]) -> Result<Value> {
    if external_public_key.len() != 32 {
        return Err(BAD_SIGNATURE);
    }
    let canonical = canonicalize(raw).map_err(|_| INVALID)?;
    let envelope: Value = serde_json::from_slice(&canonical).map_err(|_| INVALID)?;
    let fields = envelope.as_object().ok_or(INVALID)?;
    if fields.len() != 2 || !fields.contains_key("record") || !fields.contains_key("signature") {
        return Err(INVALID);
    }
    let signature = fields
        .get("signature")
        .and_then(Value::as_str)
        .ok_or(BAD_SIGNATURE)?;
    let signature = decode_base64(signature, 64).map_err(|_| BAD_SIGNATURE)?;
    let record = fields.get("record").ok_or(INVALID)?;
    let signed_bytes = canonical_value(record).map_err(|_| BAD_SIGNATURE)?;
    verify_ed25519(external_public_key, &signed_bytes, &signature).map_err(|_| BAD_SIGNATURE)?;
    Ok(record.clone())
}
