//! `CommandEnvelope` - resident op that signs and verifies the locally signed
//! envelopes around Guard Cloud's command flow.
//!
//! Faithful port of `runtime/command_capability.py`'s `_signed_payload`,
//! `_verify_signed_payload` and `_identity_digest`. Those functions minted the
//! capability the CLI issues and the grant a user writes when they confirm a
//! leased job, and decided whether a stored grant was genuine. Producing and
//! accepting an approval token is authority, so the runtime now owns the HMAC
//! and its canonical bytes; the caller reads the key out of its secret store,
//! decides when one must be minted, and persists what comes back.
//!
//! Refusal reasons are the Python codes verbatim, because `commands approve`
//! and the command audit trail surface them.

use guard_contracts::{
    command_envelope_action_supported, CommandEnvelopeRequestV1, CommandEnvelopeResultV1,
    COMMAND_ENVELOPE_ACTION_DIGEST, COMMAND_ENVELOPE_ACTION_SIGN, COMMAND_ENVELOPE_ACTION_VERIFY,
    COMMAND_ENVELOPE_MAX_BYTES, COMMAND_ENVELOPE_REQUEST_SCHEMA, COMMAND_ENVELOPE_RESULT_SCHEMA,
};
use serde_json::{json, Value};

use crate::command_capability_op::{envelope_digest, sign_envelope, verify_signed_envelope};
use crate::package_authority_op::request_digest_with_limit;

pub(crate) fn evaluate_command_envelope_request(
    request: &CommandEnvelopeRequestV1,
) -> Result<Vec<u8>, String> {
    let request_sha256 =
        request_digest(request).map_err(|_| "native_command_envelope_too_large".to_owned())?;
    let (status, code, payload) = match refusal(request) {
        Some(code) => ("error", code, None),
        None => ("ok", "ok", Some(evaluate(request))),
    };
    crate::encode_response(&CommandEnvelopeResultV1 {
        schema: COMMAND_ENVELOPE_RESULT_SCHEMA.to_owned(),
        request_id: request.request_id.clone(),
        request_sha256,
        status: status.to_owned(),
        code: code.to_owned(),
        payload,
    })
}

/// The binding digest never covers the signing key, so a caller that quotes
/// the digest in a log or a reply reveals nothing about the secret.
fn request_digest(request: &CommandEnvelopeRequestV1) -> Result<String, String> {
    let mut material =
        serde_json::to_value(request).map_err(|_| "native_command_envelope_invalid".to_owned())?;
    if let Some(object) = material.as_object_mut() {
        object.insert("integrity_key_b64".to_owned(), Value::Null);
    }
    request_digest_with_limit(&material, COMMAND_ENVELOPE_MAX_BYTES)
}

/// The conditions the op refuses rather than answers.
fn refusal(request: &CommandEnvelopeRequestV1) -> Option<&'static str> {
    // A request naming another contract is not this op's to answer: the field
    // is the sender's own statement of which request shape it built.
    if request.schema != COMMAND_ENVELOPE_REQUEST_SCHEMA {
        return Some("native_command_envelope_schema_mismatch");
    }
    // An action this runtime does not implement is refused rather than
    // answered as a failed signature, which a caller would read as a verdict.
    if !command_envelope_action_supported(&request.action) {
        return Some("native_command_envelope_action_unsupported");
    }
    None
}

fn evaluate(request: &CommandEnvelopeRequestV1) -> Value {
    let key = request.integrity_key_b64.as_deref();
    let key_id = request.integrity_key_id.as_deref();
    let answer = match request.action.as_str() {
        COMMAND_ENVELOPE_ACTION_SIGN => {
            sign_envelope(&request.payload, key, key_id).map(Value::Object)
        }
        COMMAND_ENVELOPE_ACTION_VERIFY => {
            verify_signed_envelope(&request.payload, key, key_id).map(Value::Object)
        }
        COMMAND_ENVELOPE_ACTION_DIGEST => envelope_digest(&request.payload).map(Value::from),
        // `refusal` already rejected every other action.
        _ => Err("native_command_envelope_action_unsupported"),
    };
    match answer {
        Ok(result) => json!({"accepted": true, "reason": Value::Null, "result": result}),
        Err(reason) => json!({"accepted": false, "reason": reason, "result": Value::Null}),
    }
}

#[cfg(test)]
#[path = "command_envelope_op_tests.rs"]
mod tests;
