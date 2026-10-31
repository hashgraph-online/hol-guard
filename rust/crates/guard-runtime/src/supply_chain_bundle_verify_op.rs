//! Check one signed supply-chain bundle response for a caller that holds no
//! verifier.
//!
//! [`guard_command::supply_chain_bundle`] owns the decision. This operation
//! only reads the caller's response and keyring onto that module's types and
//! reports what it answered, so the only supply-chain bundle verifier in the
//! product is the one here.

use guard_command::supply_chain_bundle::{
    load_supply_chain_bundle_response, load_supply_chain_verification_keys,
    verify_supply_chain_bundle_response, RingRsaPssVerify, SupplyChainBundleError,
};
use guard_contracts::{
    SupplyChainBundleVerifyRequestV1, SupplyChainBundleVerifyResultV1, MAX_NATIVE_REQUEST_BYTES,
    SUPPLY_CHAIN_BUNDLE_VERIFY_REQUEST_SCHEMA, SUPPLY_CHAIN_BUNDLE_VERIFY_RESULT_SCHEMA,
};
use serde_json::{json, Value};

use crate::package_authority_op::request_digest_with_limit;

/// The refusal class, so the caller raises the error its own callers already
/// distinguish rather than one opaque failure.
fn refusal_kind(error: &SupplyChainBundleError) -> &'static str {
    match error {
        SupplyChainBundleError::Signature(_) => "signature",
        SupplyChainBundleError::Expired(_) => "expired",
        SupplyChainBundleError::Rollback(_) => "rollback",
        SupplyChainBundleError::Malformed(_) => "malformed",
        SupplyChainBundleError::PayloadHash(_) => "payload_hash",
        SupplyChainBundleError::Keyring(_) => "keyring",
    }
}

fn refused(error: &SupplyChainBundleError) -> Value {
    json!({
        "outcome": "refused",
        "kind": refusal_kind(error),
        "message": error.to_string(),
    })
}

pub(crate) fn evaluate_supply_chain_bundle_verify_request(
    request: &SupplyChainBundleVerifyRequestV1,
) -> Result<Vec<u8>, String> {
    // A request this resident cannot read is not a bundle it may judge. Reading
    // an unknown schema's fields under this version's meaning would answer
    // "verified" for a request whose author meant something else.
    if request.schema != SUPPLY_CHAIN_BUNDLE_VERIFY_REQUEST_SCHEMA {
        return Err("native_supply_chain_bundle_verify_schema_mismatch".to_owned());
    }
    let request_sha256 = request_digest_with_limit(request, MAX_NATIVE_REQUEST_BYTES)
        .map_err(|_| "native_supply_chain_bundle_verify_too_large".to_owned())?;

    let payload = match verify(request) {
        Ok(()) => json!({ "outcome": "verified" }),
        Err(error) => refused(&error),
    };

    crate::encode_response(&SupplyChainBundleVerifyResultV1 {
        schema: SUPPLY_CHAIN_BUNDLE_VERIFY_RESULT_SCHEMA.to_owned(),
        request_id: request.request_id.clone(),
        request_sha256,
        status: "ok".to_owned(),
        code: "ok".to_owned(),
        payload,
    })
}

fn verify(request: &SupplyChainBundleVerifyRequestV1) -> Result<(), SupplyChainBundleError> {
    let response = load_supply_chain_bundle_response(&request.response)?;
    // An absent keyring is the bootstrap case: a caller that has saved nothing
    // accepts the keyring the response advertises. A keyring that is present
    // but lists no keys is not that case. The shared verifier skips anchoring
    // for an empty list, so letting one through would hand a caller that
    // declared a trust boundary a bundle signed by its own advertised key.
    let trusted = match &request.trusted_keys {
        None => None,
        Some(keys) => {
            let loaded = load_supply_chain_verification_keys(Some(&Value::Array(keys.clone())))?;
            if loaded.is_empty() {
                return Err(SupplyChainBundleError::Keyring(
                    "Trusted keyring is present but lists no verification keys".to_string(),
                ));
            }
            Some(loaded)
        }
    };
    verify_supply_chain_bundle_response(
        &response,
        trusted.as_deref(),
        request.cached_bundle_version.as_deref(),
        request.now,
        &RingRsaPssVerify,
    )
}

#[cfg(test)]
#[path = "supply_chain_bundle_verify_op_tests.rs"]
mod tests;
