//! Authenticate the injection probe before pure attribution. The enclosing
//! control and SDK result still need independent custody and effect evidence.

use crate::crypto::decode_hex;
use crate::{canonical_value, reduce_injection_attribution, verify_controller_envelope};
use crate::{EvidenceError, Result};
use gauntlet_contracts::canonicalize;
use serde_json::Value;

const INVALID: EvidenceError = EvidenceError::Invalid("invalid injection control record");
const WRONG_KEY: EvidenceError = EvidenceError::Invalid("control key differs from outside pin");

/// Verify the signed `extra_probes` envelope against an outside Ed25519 key,
/// then compute only the injection intervention from its authenticated probe
/// and the supplied control's SDK result. The SDK result, kernel samples and
/// product effects are not authenticated here; this never awards a pass.
pub fn reduce_signed_injection_attribution(
    raw_control: &[u8],
    external_public_key: &[u8],
) -> Result<Value> {
    let canonical = canonicalize(raw_control).map_err(|_| INVALID)?;
    let mut control: Value = serde_json::from_slice(&canonical).map_err(|_| INVALID)?;
    let fields = control.as_object_mut().ok_or(INVALID)?;
    let declared = fields
        .get("controller_public_key_hex")
        .and_then(Value::as_str)
        .ok_or(WRONG_KEY)?;
    let declared = decode_hex(declared, 32).map_err(|_| WRONG_KEY)?;
    if declared != external_public_key {
        return Err(WRONG_KEY);
    }
    let envelope = fields.get("extra_probes").ok_or(INVALID)?;
    let envelope_bytes = canonical_value(envelope).map_err(|_| INVALID)?;
    let signed_probe = verify_controller_envelope(&envelope_bytes, external_public_key)?;
    fields.insert("extra_probes".into(), signed_probe);
    reduce_injection_attribution(&control)
}
