//! Entry point of the `CommandCapability` resident op.
//!
//! A caller whose store is the encrypted-file vault sends `resident_key`, and
//! the resident reads the signing key from that vault itself, so no secret
//! crosses the wire. A caller whose key lives in the system keyring still
//! sends its copy. The reply's binding digest covers the request as sent.

use std::path::Path;

use guard_contracts::{
    CommandCapabilityRequestV1, CommandCapabilityResultV1, COMMAND_CAPABILITY_RESULT_SCHEMA,
};

use super::{evaluate, refusal, request_digest};
use crate::command_envelope_op::resident_key;

pub(crate) fn evaluate_command_capability_request(
    request: &CommandCapabilityRequestV1,
    guard_home: Option<&Path>,
) -> Result<Vec<u8>, String> {
    let request_sha256 =
        request_digest(request).map_err(|_| "native_command_capability_too_large".to_owned())?;
    let (status, code, payload) = match refusal(request).or_else(|| resident_refusal(request)) {
        Some(code) => ("error", code, None),
        None => ("ok", "ok", Some(evaluate(&keyed(request, guard_home)))),
    };
    crate::encode_response(&CommandCapabilityResultV1 {
        schema: COMMAND_CAPABILITY_RESULT_SCHEMA.to_owned(),
        request_id: request.request_id.clone(),
        request_sha256,
        status: status.to_owned(),
        code: code.to_owned(),
        payload,
    })
}

/// Asking for the resident's key while sending a key or a key id leaves two
/// keys, and the op will not pick between them. Checked after `refusal`, so
/// a request for another schema is still refused as a schema mismatch.
fn resident_refusal(request: &CommandCapabilityRequestV1) -> Option<&'static str> {
    (request.resident_key
        && (request.integrity_key_b64.is_some() || request.integrity_key_id.is_some()))
    .then_some("native_command_capability_invalid")
}

/// The request as the verifier reads it: with `resident_key`, the key and id
/// the resident's own vault holds for `guard_home`. No home or no stored key
/// is no key, which the verifier refuses as `local_signing_key_unavailable`.
fn keyed(
    request: &CommandCapabilityRequestV1,
    guard_home: Option<&Path>,
) -> CommandCapabilityRequestV1 {
    let mut keyed = request.clone();
    if request.resident_key {
        let (key, key_id) = resident_key(guard_home);
        keyed.integrity_key_b64 = key;
        keyed.integrity_key_id = key_id;
    }
    keyed
}

#[cfg(test)]
#[path = "command_capability_resident_key_tests.rs"]
mod tests;
